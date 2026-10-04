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

  // Global lookups and dependency inversion tracking
  const finderFindingsMap = new Map();
  const incomingLinksMap = new Map(); // Key: file being imported, Value: set of files importing it

  // Using the finder's locallinks to build the graph
  findings.forEach(node => {
    const normalisedPath = path.normalize(node.filePath);
    finderFindingsMap.set(normalisedPath, node);

    if (node.localLinks && Array.isArray(node.localLinks)) {
      node.localLinks.forEach(linkedFile => {
        const normalisedLink = path.normalize(linkedFile);

        if (!incomingLinksMap.has(normalisedLink)) {
          incomingLinksMap.set(normalisedLink, new Set());
        }
        // Invert the edge: map the target dependency back to its consumer
        incomingLinksMap.get(normalisedLink).add(normalisedPath);
      });
    }
  });

  // Defines operational entry criteria
  function isRuntimeApplicationRoot(normalisedPath) {
    // Systems bins and boots are always runtime roots
    if (
      normalisedPath.includes(path.join('src', 'bin')) ||
      normalisedPath.endsWith('bootstrap.ts') ||
      normalisedPath.endsWith('bootstrap.js')
    ) {
      return true;
    }

    if (normalisedPath.includes(path.join('pages'))) {
      const parentDir = path.dirname(normalisedPath);
      return fs.existsSync(path.join(parentDir, 'route.json'));
    }

    return false;
  }

  // Tracks reachability maps per vulnerability signature
  const verifiedReachablePackages = new Set();
  const evaluatedVulnerableFiles = findings.filter(f => f.status === 'PENDING_EVALUATION');

  console.log(`Analysing ${evaluatedVulnerableFiles.length} vulnerable target nodes discovered by finder...`);

  // Traces upward for every vulnerable file found
  evaluatedVulnerableFiles.forEach(vulnerableNode => {
    const startPath = path.normalize(vulnerableNode.filePath);
    const targetPackageName = vulnerableNode.meta && vulnerableNode.meta.package;

    const traversalQueue = [startPath];
    const visitedInThisTrace = new Set([startPath]);
    let traceIsReachable = false;

    while (traversalQueue.length > 0) {
      const currentFile = traversalQueue.shift();

      // If this branch touches a valid operational framework asset root, it is live code
      if (isRuntimeApplicationRoot(currentFile)) {
        traceIsReachable = true;
        break;
      }

      // Look up who imports the current file to step backward
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

    // If the path reached a verified application asset root, save the package signature
    if (traceIsReachable && targetPackageName) {
      verifiedReachablePackages.add(targetPackageName);
    }
  });

    // Compiles the result payload
    const finalFindings = findings.map(node => {
      let vulnerabilityStatus = node.status;

      if (node.status === 'PENDING_EVALUATION') {
        const pkgIdentifier = node.meta && node.meta.package;
        // Re-evaluates if this package is actually hit on any valid runtime execution track
        vulnerabilityStatus = verifiedReachablePackages.has(pkgIdentifier) ? 'REACHABLE' : 'MUTED';
      }

    const findingRecord = {
      filePath: node.filePath,
      status: vulnerabilityStatus
    };
    if (node.meta) {
      findingRecord.meta = node.meta;
    }
    return findingRecord;
  });

  const outputPayload = {
    generatedAt: new Date().toISOString(),
    findings: finalFindings
  };

  fs.writeFileSync('reachability-results.json', JSON.stringify(outputPayload, null, 2), 'utf8');

  // Print diagnostics mapping
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