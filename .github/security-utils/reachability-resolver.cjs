const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (err) {
    console.error(`RESOLVER ERROR: Cannot read ${filePath}`);
    process.exit(1);
  }
}

function gatherAllSourceFiles(dirPath, filesArray = []) {
  if (!fs.existsSync(dirPath)) return filesArray;
  const items = fs.readdirSync(dirPath);

  items.forEach(item => {
    const fullPath = path.join(dirPath, item);
    if (fs.statSync(fullPath).isDirectory()) {
      gatherAllSourceFiles(fullPath, filesArray);
    } else {
      if (/\.test\.(js|jsx|ts|tsx)\$/.test(item)) return;
      if (/\.(js|jsx|ts|tsx|json)\$/.test(fullPath)) {
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

  const codebaseInventory = gatherAllSourceFiles(appSrcDir);

  const finderFindingsMap = new Map();
  rawFinderOutput.findings.forEach(f => {
    finderFindingsMap.set(path.normalize(f.filePath), f);
  });

  // Tracks how many times an internal application file is targeted by another file's imports
  const inboundUsageCounts = new Map();
  codebaseInventory.forEach(file => {
    inboundUsageCounts.set(path.normalize(file), 0);
  });

  // Walks through the localLinks extracted by the finder to calculate inbound weights
  rawFinderOutput.findings.forEach(f => {
    if (f.localLinks && Array.isArray(f.localLinks)) {
      f.localLinks.forEach(linkedFile => {
        const normalisedLink = path.normalize(linkedFile);
        if (inboundUsageCounts.has(normalisedLink)) {
          inboundUsageCounts.set(normalisedLink, inboundUsageCounts.get(normalisedLink) + 1);
        }
      });
    }
  });

  const traversalQueue = [];
  const visitedFiles = new Set();

  // Seeds graph traversal queue using public entry points
  codebaseInventory.forEach(file => {
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
      if (finderNode.status === 'PENDING_EVALUATION' && finderNode.meta && finderNode.meta.package) {
        activeThirdPartyPackagesEncountered.add(finderNode.meta.package);
      }

      if (finderNode.localLinks && Array.isArray(finderNode.localLinks)) {
        finderNode.localLinks.forEach(linkedFile => {
          const normalisedLink = path.normalize(linkedFile);
          if (!visitedFiles.has(normalisedLink)) {
            visitedFiles.add(normalisedLink);
            traversalQueue.push(normalisedLink);
          }
        });
      }
    }
  }

  const finalFindings = [];

  // Map application source files using the reference maps
  codebaseInventory.forEach(file => {
    const normalisedFile = path.normalize(file);
    const finderNode = finderFindingsMap.get(normalisedFile);
    const totalInboundReferences = inboundUsageCounts.get(normalisedFile) || 0;

    let vulnerabilityStatus = 'SAFE';

    const isExplicitEntryRoot =
      (normalisedFile.includes(path.join('src', 'bin')) && !normalisedFile.includes(path.join('bin', 'lib'))) ||
      normalisedFile.includes(path.join('pages')) ||
      normalisedFile.endsWith('bootstrap.ts') ||
      normalisedFile.endsWith('bootstrap.js');

    if (visitedFiles.has(normalisedFile)) {
      if (finderNode) {
        if (finderNode.status === 'AMBIGUOUS') {
          vulnerabilityStatus = 'AMBIGUOUS';
        } else if (finderNode.status === 'PENDING_EVALUATION') {

          if (!isExplicitEntryRoot && totalInboundReferences === 0) {
            vulnerabilityStatus = 'MUTED';
          } else {
            vulnerabilityStatus = 'REACHABLE';
          }
        }
      }
    } else {
      vulnerabilityStatus = 'MUTED';
    }

    const findingRecord = {
      filePath: file,
      status: vulnerabilityStatus
    };
    if (finderNode && finderNode.meta) {
      findingRecord.meta = finderNode.meta;
    }
    finalFindings.push(findingRecord);
  });

  // Map external third-party entries from our Finder payload
  rawFinderOutput.findings.forEach(finding => {
    const normalisedNodePath = path.normalize(finding.filePath);
    if (codebaseInventory.some(f => path.normalize(f) === normalisedNodePath)) return;

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