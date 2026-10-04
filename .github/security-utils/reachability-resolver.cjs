const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (err) {
    console.error(`RESOLVER ERROR: Cannot read ${filePath}`);
    process.exit(1);
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
      if (/\.(js|jsx|ts|tsx|json)$/.test(fullPath)) {
        filesArray.push(path.normalize(path.relative(process.cwd(), fullPath)));
      }
    }
  });
  return filesArray;
}

function runReachabilityResolver() {
  console.log("=== Running reachability resolver ===");

  const rawVulnerabilitiesPath = 'dependency-vulnerabilities.json';
  if (!fs.existsSync(rawVulnerabilitiesPath)) {
    console.error(`RESOLVER ERROR: Missing input file (${rawVulnerabilitiesPath})`);
    process.exit(1);
  }

  const rawFinderOutput = safeReadJson(rawVulnerabilitiesPath);
  const appSrcDir = path.join('packages', 'evershop', 'src');

  // Discover every single asset to establish our full baseline contract space
  const completeCodebaseInventory = gatherAllSourceFiles(appSrcDir);

  // Indexes the finder dictionary map for efficient lookups
  const finderFindingsMap = new Map();
  rawFinderOutput.findings.forEach(f => {
    finderFindingsMap.set(path.normalize(f.filePath), f);
  });

  const traversalQueue = [];
  const visitedFiles = new Set();

  // Seed graph traversal queue using public entry points
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

  console.log(`Seeded graph traversal queue with ${traversalQueue.length} vulnerability entry points.\n`);

  const activeThirdPartyPackagesEncountered = new Set();

  while (traversalQueue.length > 0) {
    const currentFile = traversalQueue.shift();
    const finderNode = finderFindingsMap.get(currentFile);

    if (finderNode) {
      // If the finder previously flagged this live file as a risk, mark it encountered
      if (finderNode.status === 'PENDING_EVALUATION' && finderNode.meta && finderNode.meta.package) {
        activeThirdPartyPackagesEncountered.add(finderNode.meta.package);
      }

      // Traversal walks down pre-computed local links supplied by
      // the dependency vulnerability finder
      if (finderNode.localLinks && Array.isArray(finderNode.localLinks)) {
        finderNode.localLinks.forEach(linkedFile => {
          const normalizedLink = path.normalize(linkedFile);
          if (!visitedFiles.has(normalizedLink)) {
            visitedFiles.add(normalizedLink);
            traversalQueue.push(normalizedLink);
          }
        });
      }
    }
  }

  const finalFindings = [];

  // Map application source files using the pre-compiled lookup dictionary
  completeCodebaseInventory.forEach(file => {
    const normalizedFile = path.normalize(file);
    const finderNode = finderFindingsMap.get(normalizedFile);
    let structuralStatus = 'SAFE';

    if (visitedFiles.has(normalizedFile)) {
      if (finderNode) {
        if (finderNode.status === 'AMBIGUOUS') {
          structuralStatus = 'AMBIGUOUS';
        } else if (finderNode.status === 'PENDING_EVALUATION') {
          structuralStatus = 'REACHABLE';
        }
      }
    } else {
      structuralStatus = 'MUTED';
    }

    const findingRecord = {
      filePath: file,
      status: structuralStatus
    };
    if (finderNode && finderNode.meta) {
      findingRecord.meta = finderNode.meta;
    }
    finalFindings.push(findingRecord);
  });

  // Map external third-party entries from our Finder payload
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
  const ambiguousCount = finalFindings.filter(f => f.status === 'AMBIGUOUS').length;
  const mutedCount = finalFindings.filter(f => f.status === 'MUTED').length;

  console.log(`📊 Resolution summary`);
  console.log(`Total evaluated: ${totalEvaluated} target records`);
  console.log("---");
  console.log(`🔴 REACHABLE risks: ${reachableCount}`);
  console.log(`🟡 WARNINGS: ${ambiguousCount}`);
  console.log(`⚪ MUTED risks: ${mutedCount}`);
}

runReachabilityResolver();