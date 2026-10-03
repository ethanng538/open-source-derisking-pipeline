const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (err) {
    console.error(`RESOLVER ERROR: Cannot read ${filePath}`);
    process.exit(1);
  }
}

const fileContentCache = new Map();
function getCachedFileContent(filePath) {
  if (fileContentCache.has(filePath)) return fileContentCache.get(filePath);
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    fileContentCache.set(filePath, content);
    return content;
  } catch (e) {
    fileContentCache.set(filePath, '');
    return '';
  }
}

// Builds the complete codebase inventory map
function gatherAllSourceFiles(dirPath, filesArray = []) {
  if (!fs.existsSync(dirPath)) return filesArray;
  const items = fs.readdirSync(dirPath);

  items.forEach(item => {
    const fullPath = path.join(dirPath, item);
    if (fs.statSync(fullPath).isDirectory()) {
      gatherAllSourceFiles(fullPath, filesArray);
    } else {
      if (/\.(js|jsx|ts|tsx|json)\$/.test(fullPath)) {
        filesArray.push(path.normalize(path.relative(process.cwd(), fullPath)));
      }
    }
  });
  return filesArray;
}

function extractLocalImports(filePath, fileContent) {
  const imports = [];
  // Common import patterns
  const relativeImportRegex = /(?:require\s*\(\s*['"](\..*?)['"]\s*\)|from\s+['"](\..*?)['"]|import\s+['"](\..*?)['"])/g;

  let match;
  const currentDir = path.dirname(filePath);

  while ((match = relativeImportRegex.exec(fileContent)) !== null) {
    const relativeTarget = match[1] || match[2] || match[3];
    if (!relativeTarget) continue;

    let absoluteTarget = path.resolve(currentDir, relativeTarget);
    const extensionsToTry = ['', '.ts', '.tsx', '.js', '.jsx', '/index.ts', '/index.js'];
    for (const ext of extensionsToTry) {
      const pathWithExt = absoluteTarget + ext;
      if (fs.existsSync(pathWithExt) && fs.statSync(pathWithExt).isFile()) {
        imports.push(path.normalize(path.relative(process.cwd(), pathWithExt)));
        break;
      }
    }
  }
  return imports;
}

function runReachabilityResolver() {
  console.log("=== Running reachability resolver ===");

  const rawVulnerabilitiesPath = 'vulnerable-dependencies.json';
  if (!fs.existsSync(rawVulnerabilitiesPath)) {
    console.error(`RESOLVER ERROR: Missing input file (${rawVulnerabilitiesPath})`);
    process.exit(1);
  }

  const rawFinderOutput = safeReadJson(rawVulnerabilitiesPath);
  const appSrcDir = path.join('packages', 'evershop', 'src');

  // Discover every single asset to establish our full baseline contract space
  const completeCodebaseInventory = gatherAllSourceFiles(appSrcDir);

  const activePackageTargets = new Set();
  rawFinderOutput.findings.forEach(f => {
    if (f.meta && f.meta.package) activePackageTargets.add(f.meta.package);
  });

  const traversalQueue = [];
  const visitedFiles = new Set();

  completeCodebaseInventory.forEach(file => {
    const normalised = path.normalize(file);
    if (
      normalised.includes(path.join('src', 'bin')) ||
      normalised.includes(path.join('pages')) ||
      normalised.endsWith('bootstrap.ts') ||
      normalised.endsWith('bootstrap.js')
    ) {
      traversalQueue.push(normalised);
      visitedFiles.add(normalised);
    }
  });

  console.log(`Seeded graph traversal queue with ${traversalQueue.length} vulnerability entry points.`);

  const activeThirdPartyPackagesEncountered = new Set();
  const sourceFileStatusMap = new Map(); // Tracks dynamic findings

  while (traversalQueue.length > 0) {
    const currentFile = traversalQueue.shift();
    const content = getCachedFileContent(currentFile);
    let currentFileStatus = 'SAFE';

    if (/require\s*\([^'"]*?[\+\$`]/g.test(content) || /import\s*\([^'"]*?[\+\$`]/g.test(content)) {
      currentFileStatus = 'WARNING';
    }

    // Evaluate direct third-party vulnerability imports
    for (const pkgName of activePackageTargets) {
      const importRegex = new RegExp(`(require\\(['"]${pkgName}['"]\\)|from\\s+['"]${pkgName}['"]|import\\s+['"]${pkgName}['"])`, 'g');
      if (importRegex.test(content)) {
        currentFileStatus = 'REACHABLE';
        activeThirdPartyPackagesEncountered.add(pkgName);
      }
    }

    sourceFileStatusMap.set(currentFile, currentFileStatus);

    // Extract next structural branches and append unvisited local files onto the queue
    const localLinks = extractLocalImports(currentFile, content);
    localLinks.forEach(linkedFile => {
      if (!visitedFiles.has(linkedFile)) {
        visitedFiles.add(linkedFile);
        traversalQueue.push(linkedFile);
      }
    });
  }

  const finalFindings = [];

  // Map application source files
  completeCodebaseInventory.forEach(file => {
    const normalizedFile = path.normalize(file);
    let structuralStatus = 'SAFE';

    if (visitedFiles.has(normalizedFile)) {
      structuralStatus = sourceFileStatusMap.get(normalizedFile) || 'SAFE';
    } else {
      // Unvisited code contains a vulnerability signature from the finder? It's proven to be dead MUTED code.
      const listedInFinder = rawFinderOutput.findings.some(f => path.normalize(f.filePath) === normalizedFile);
      structuralStatus = listedInFinder ? 'MUTED' : 'SAFE';
    }

    finalFindings.push({
      filePath: file,
      status: structuralStatus
    });
  });

  // Map third-party node_modules entry points from our finder payload
  rawFinderOutput.findings.forEach(finding => {
    const normalizedNodePath = path.normalize(finding.filePath);
    if (completeCodebaseInventory.some(f => path.normalize(f) === normalizedNodePath)) return;

    const pkgIdentifier = finding.meta && finding.meta.package;
    const dependencyStatus = activeThirdPartyPackagesEncountered.has(pkgIdentifier) ? 'REACHABLE' : 'MUTED';

    finalFindings.push({
      filePath: finding.filePath,
      status: dependencyStatus,
      meta: finding.meta
    });
  });

  const outputPayload = {
    generatedAt: new Date().toISOString(),
    findings: finalFindings
  };

  fs.writeFileSync('reachability-results.json', JSON.stringify(outputPayload, null, 2), 'utf8');

  const totalEvaluated = finalFindings.length;
  const reachableCount = finalFindings.filter(f => f.status === 'REACHABLE').length;

  console.log(`📊 Resolution summary`);
  console.log(`Total evaluated: ${totalEvaluated} target records`);
  console.log("---");
  console.log(`🔴 REACHABLE risks: ${reachableCount}`);
}

runReachabilityResolver();