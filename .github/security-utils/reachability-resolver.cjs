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

// Evaluates whether a file is an implicit entry point bound by EverShop conventions
function isFrameworkEntryPoint(normalisedPath) {

  return (
    normalisedPath.includes('/src/pages/') ||
    normalisedPath.includes('/src/api/') ||
    normalisedPath.includes('/src/graphql/') ||
    normalisedPath.includes('/src/subscribers/') ||
    normalisedPath.includes('/src/migration/') ||
    normalisedPath.endsWith('/bootstrap.ts') ||
    normalisedPath.endsWith('/bootstrap.js')

  );
}

function runReachabilityResolver() {
  console.log("=== Running reachability-resolver ===");

  const potentialVulnerabilitiesPath = 'dependency-vulnerabilities.json';
  if (!fs.existsSync(potentialVulnerabilitiesPath)) {
    console.error(`RESOLVER ERROR: Missing input file (${potentialVulnerabilitiesPath})`);
    process.exit(1);
  }

  const dependencyVulnerabilityFinderOutput = safeReadJson(potentialVulnerabilitiesPath);
  const potentialVulnerabilities = dependencyVulnerabilityFinderOutput.findings;

  const incomingLinksMap = new Map(); // Key: file being imported, Value: set of files importing it

  potentialVulnerabilities.forEach(node => {
    const normalisedPath = path.normalize(node.filePath);

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

  const verifiedReachableFiles = new Set();
  const evaluatedVulnerableFiles = potentialVulnerabilities.filter(f => f.status === 'PENDING_EVALUATION');

  console.log(`Analysing ${evaluatedVulnerableFiles.length} vulnerable target nodes discovered by finder...`);

  evaluatedVulnerableFiles.forEach(vulnerableNode => {
    const startPath = path.normalize(vulnerableNode.filePath);

    const traversalQueue = [startPath];
    const visitedInThisTrace = new Set([startPath]);
    let traceIsReachable = false;

    while (traversalQueue.length > 0) {
      const currentFile = traversalQueue.shift();

      if (isFrameworkEntryPoint(currentFile)) {
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
  const findings = [];
  const resolverRecords = [];

  potentialVulnerabilities.forEach(node => {
    const normalisedPath = path.normalize(node.filePath);
    let vulnerabilityStatus = node.status;

    if (node.status === 'PENDING_EVALUATION') {
      vulnerabilityStatus = verifiedReachableFiles.has(normalisedPath) ? 'REACHABLE' : 'MUTED';
    }

    resolverRecords.push(node.filePath);

    if (vulnerabilityStatus === 'SAFE') {
      return;
    }

    const findingRecord = {
      filePath: normalisedPath,
      status: vulnerabilityStatus
    };

    if (node.meta) {
      findingRecord.meta = node.meta;
    }

    findings.push(findingRecord);
  });

  const timestamp = new Date().toISOString();

  fs.writeFileSync('reachability-results.json', JSON.stringify({
    generatedAt: timestamp,
    findings: findings,
    records: resolverRecords
  }, null, 2), 'utf8');

  fs.writeFileSync('resolver-evaluation-record.json', JSON.stringify({
    generatedAt: timestamp,
    summary: {
      totalInputRecords: potentialVulnerabilities.length,
      findingsLogged: findings.length
    },
    records: resolverRecords
  }, null, 2), 'utf8');

  const totalEvaluated = findings.length;
  const reachableCount = findings.filter(f => f.status === 'REACHABLE').length;
  const ambiguousCount = findings.filter(f => f.status === 'AMBIGUOUS').length;
  const mutedCount = findings.filter(f => f.status === 'MUTED').length;

  console.log(`\n📊 Resolution summary`);
  console.log(`Total evaluated: ${totalEvaluated} target records`);
  console.log("---");
  console.log(`🔴 REACHABLE risks: ${reachableCount}`);
  console.log(`🟡 WARNINGS: ${ambiguousCount}`);
  console.log(`⚪ MUTED risks: ${mutedCount}`);
}

runReachabilityResolver();