const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`CONFIG ERROR: Failed to read or parse file at ${filePath}`);
    process.exit(1);
  }
}


function runSafetyNet() {
  let pipelineFailed = false;
  const errorLog = [];
  const warningLog = [];

  console.log("=== Phase 1: Structural validation ===");
  if (!fs.existsSync('vulnerable-dependencies.json')) {
    console.error("PHASE 1 ERROR: 'vulnerable-dependencies.json' not found. Engine did not run.");
    process.exit(1);
  }

  const engineOutput = safeReadJson('vulnerable-dependencies.json');
  if (!engineOutput.findings || !Array.isArray(engineOutput.findings)) {
    console.error("PHASE 1 ERROR: Engine payload is missing a valid 'findings' array.");
    process.exit(1);
  }

  console.log("✅ PHASE 1 PASSED: Output matches required structural schema contract.");

  console.log("\n=== Phase 2: Reachability verification ===");
  const graphPath = process.env.COMPILATION_GRAPH_PATH || 'compilation-graph.json';

  if (!fs.existsSync(graphPath)) {
    console.error(`PHASE 2 ERROR: '${graphPath}' not found. Compiler telemetry graph is missing.`);
    process.exit(1);
  }

  const webpackGraph = safeReadJson(graphPath);

  const compiledAssetGraph = new Set([
    ...(webpackGraph.frontend || []),
    ...(webpackGraph.backend || [])
  ].map(p => path.normalize(p)));

  const engineFiles = new Set();
  let totalRecordsChecked = 0;
  let counts = { REACHABLE: 0, MUTED: 0, WARNING: 0 };

  for (const finding of engineOutput.findings) {
    if (!finding.filePath || !finding.status) {
      errorLog.push(`Malformed record structure found at index ${totalRecordsChecked}`);
      pipelineFailed = true;
      totalRecordsChecked++;
      continue;
    }

    const normalisedPath = path.normalize(finding.filePath);
    const isAssetCompiled = compiledAssetGraph.has(normalisedPath);

    // Multi-state breach check
    if (engineFiles.has(normalisedPath) && finding.status !== 'PENDING_EVALUATION') {
      errorLog.push(`MULTI-STATE BREACH: File '${finding.filePath}' was defined multiple times with conflicting explicit states.`);
      pipelineFailed = true;
    }

    if (engineFiles.has(normalisedPath) && finding.status === 'PENDING_EVALUATION') {
      totalRecordsChecked++;
      continue;
    }

    let effectiveStatus = finding.status;
    if (finding.status === 'PENDING_EVALUATION') {
      effectiveStatus = isAssetCompiled ? 'REACHABLE' : 'MUTED';
    }

    counts[effectiveStatus] = (counts[effectiveStatus] || 0) + 1;

    // Inclusion (Reachable): if a file is a live risk, it must actively exist in the compiled asset graph.
    if (effectiveStatus === 'REACHABLE' && !isAssetCompiled) {
      errorLog.push(`LOGIC BREACH: Engine flagged '${finding.filePath}' as REACHABLE but it is completely missing from the active build graphs.`);
      pipelineFailed = true;
    }

    // Exclusion (Muted): if flagged as dead code or tree-shaken, it cannot actively exist inside the compiled assets.
    if (effectiveStatus === 'MUTED' && isAssetCompiled) {
      errorLog.push(`LOGIC BREACH: Engine flagged '${finding.filePath}' as MUTED but it actively exists inside compiled assets.`);
      pipelineFailed = true;
    }

    if (effectiveStatus === 'WARNING') {
      warningLog.push(`Unresolved dynamic reference or wildcard evaluation found in: '${finding.filePath}'`);
    }

    engineFiles.add(normalisedPath);
    totalRecordsChecked++;
  }

  const auditPath = 'npm-audit.json';
  let totalAuditVulnerabilities = 0;
  if (fs.existsSync(auditPath)) {
    const auditData = safeReadJson(auditPath);
    totalAuditVulnerabilities = auditData.vulnerabilities ? Object.keys(auditData.vulnerabilities).length : 0;
  }

  if (totalRecordsChecked === 0) {
    if (totalAuditVulnerabilities > 0) {
      errorLog.push(`ZERO RECORD BREACH: The engine evaluated 0 files but 'npm-audit.json' contains ${totalAuditVulnerabilities} active vulnerabilities.`);
      pipelineFailed = true;
    } else {
      console.log(" Zero records found because the project package manifest has 0 vulnerabilities.");
    }
  }

  // Completeness reverse-audit: ensures the analysis engine didn't bypass any file actively bundled by the compilers.
  if (webpackGraph.appSource && Array.isArray(webpackGraph.appSource)) {
    for (const sourceAsset of webpackGraph.appSource) {
      if (!engineFiles.has(sourceAsset)) {
        errorLog.push(`COMPLETENESS BREACH: The compiler bundled custom source module '${sourceAsset}' but the analysis engine bypassed evaluating it.`);
        pipelineFailed = true;
      }
    }
  }

  // Evaluate statistical distribution
  if (totalRecordsChecked > 0 && counts.REACHABLE === 0 && counts.MUTED === 0) {
    errorLog.push(`TRIVIAL PAYLOAD BREACH: Engine failed statistical distribution check. Found REACHABLE: ${counts.REACHABLE}, MUTED: ${counts.MUTED}.`);
    pipelineFailed = true;
  }

  // Handle final reporting
  if (pipelineFailed) {
    console.error(`🚨 PHASE 2 FAILED: Invariant Matrix validation failed with ${errorLog.length} breach(es):`);
    errorLog.forEach((err, index) => {
      console.error(`  [${index + 1}] ${err}`);
    });
    console.error("\n❌ Pipeline terminated due to compilation telemetry alignment violations.");
    process.exit(1);
  }

  const diagnosticPayload = {
    timestamp: new Date().toISOString(),
    counts: counts,
    totalChecked: totalRecordsChecked,
    errors: errorLog,
    warnings: warningLog,
    webpackGraphSize: compiledAssetGraph.size,
    engineFilesSize: engineFiles.size
  };

  fs.writeFileSync(
    path.join(process.cwd(), 'validator-diagnostics.json'),
    JSON.stringify(diagnosticPayload, null, 2),
    'utf8'
  );

  console.log("✅ PHASE 2 PASSED: Live graph intersection matches live compiler telemetry mapping.\n");

  if (warningLog.length > 0) {
    console.warn(`⚠️  ENGINE ALERT: Triage required for ${warningLog.length} unresolved dynamic/wildcard reference(s):`);
    warningLog.forEach((warn, index) => {
      console.warn(`  [${index + 1}] ${warn}`);
    });
    console.warn("");
  }

  console.log(`\nSUCCESS: Security pipeline logic safely validated across ${totalRecordsChecked} records.`);
  process.exit(0);
}

runSafetyNet();