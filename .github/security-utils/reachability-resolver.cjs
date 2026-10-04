const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`RESOLVER ERROR: Cannot read ${filePath}`);
    process.exit(1);
  }
}

function runReachabilityResolver() {
  console.log("=== Running reachability-resolver ===");

  const rawVulnerabilitiesPath = 'dependency-vulnerabilities.json';
  if (!fs.existsSync(rawVulnerabilitiesPath)) {
    console.error(`RESOLVER ERROR: Missing input file (${rawVulnerabilitiesPath})`);
    process.exit(1);
  }

  const rawFinderOutput = safeReadJson(rawVulnerabilitiesPath);
  const findings = rawFinderOutput.findings;

  const finderFindingsMap = new Map();
  const incomingLinksMap = new Map(); // Key: file being imported, Value: set of files importing it

  // Builds the graph utilising the finder's pre-computed localLinks
  findings.forEach(node => {
    const normalisedPath = path.normalize(node.filePath);
    finderFindingsMap.set(normalisedPath, node);

    if (node.localLinks && Array.isArray(node.localLinks)) {
      node.localLinks.forEach(linkedFile => {
        const normalisedLink = path.normalize(linkedFile);

        if (!incomingLinksMap.has(normalisedLink)) {
          incomingLinksMap.set(normalisedLink, new Set());
        }
        incomingLinksMap.get(normalisedLink).add(normalisedPath);
      });
    }
  });

  // Defines operational application entry criteria
  function isRuntimeApplicationRoot(normalisedPath) {
    const incomingImports = incomingLinksMap.get(normalisedPath);
    const totalInboundReferences = incomingImports ? incomingImports.size : 0;

    if (normalisedPath.includes(path.join('pages'))) {
      const parentDir = path.dirname(normalisedPath);
      const hasRouteJson = fs.existsSync(path.join(parentDir, 'route.json'));

      return hasRouteJson && totalInboundReferences > 0;
    }

    return false;
  }

  const verifiedReachableFiles = new Set();
  const evaluatedVulnerableFiles = findings.filter(f => f.status === 'PENDING_EVALUATION');

  console.log(`Analysing ${evaluatedVulnerableFiles.length} vulnerable target nodes discovered by finder...`);

  evaluatedVulnerableFiles.forEach(vulnerableNode => {
    const startPath = path.normalize(vulnerableNode.filePath);

    const traversalQueue = [startPath];
    const visitedInThisTrace = new Set([startPath]);
    let traceIsReachable = false;

    while (traversalQueue.length > 0) {
      const currentFile = traversalQueue.shift();

      if (isRuntimeApplicationRoot(currentFile)) {
        traceIsReachable = true;
        break;
      }

      const upstreamImporters = incomingLinksMap.get(currentFile);
      if (upstreamImporters) {
        upstreamImporters.forEach(importer => {
          if (!visitedInThisTrace.has(importer)) {
            visitedInThisTrace.add(importer);
            traversalQueue.push(importer);
          }
        });
      }
    }

    if (traceIsReachable) {
      verifiedReachableFiles.add(startPath);
    }
  });

  // Compile final clean payload mapping
  const finalFindings = [];

  findings.forEach(node => {
    const normalisedPath = path.normalize(node.filePath);
    let vulnerabilityStatus = node.status;

    if (node.status === 'PENDING_EVALUATION') {
      vulnerabilityStatus = verifiedReachableFiles.has(normalisedPath) ? 'REACHABLE' : 'MUTED';
    }

    if (vulnerabilityStatus === 'SAFE') {
      return;
    }

    const findingRecord = {
      filePath: node.filePath,
      status: vulnerabilityStatus
    };

    if (node.meta) {
      findingRecord.meta = node.meta;
    }

    finalFindings.push(findingRecord);
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

  console.log(`\n📊 Resolution summary`);
  console.log(`Total evaluated: ${totalEvaluated} target records`);
  console.log("---");
  console.log(`🔴 REACHABLE risks: ${reachableCount}`);
  console.log(`🟡 WARNINGS: ${ambiguousCount}`);
  console.log(`⚪ MUTED risks: ${mutedCount}`);
}

runReachabilityResolver();