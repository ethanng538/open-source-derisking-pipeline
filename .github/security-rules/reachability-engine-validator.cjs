const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`🚨 CRITICAL CONFIG ERROR: Failed to read or parse file at ${filePath}`);
    process.exit(1);
  }
}


function runSafetyNet() {
  let pipelineFailed = false;
  const errorLog = [];
  const warningLog = [];

  console.log("=== Phase 1: Structural validation ===");
  if (!fs.existsSync('reachability-results.json')) {
    console.error("🚨 PHASE 1 CRITICAL: 'reachability-results.json' not found. Engine did not run.");
    process.exit(1);
  }

  const engineOutput = safeReadJson('reachability-results.json');
  if (!engineOutput.findings || !Array.isArray(engineOutput.findings)) {
    console.error("🚨 PHASE 1 CRITICAL: Engine payload is missing a valid 'findings' array.");
    process.exit(1);
  }

  console.log("✅ PHASE 1 PASSED: Output matches required structural schema contract.");

  console.log("\n=== Phase 2: Invariant Matrix Telemetry Verification ===");
  const graphPath = process.env.COMPILATION_GRAPH_PATH || 'compilation-graph.json';

  if (!fs.existsSync(graphPath)) {
    console.error(`🚨 PHASE 2 CRITICAL: '${graphPath}' not found. Compiler telemetry graph is missing.`);
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
    counts[finding.status] = (counts[finding.status] || 0) + 1;

    // Multi-state breach check
    if (engineFiles.has(normalisedPath)) {
      errorLog.push(`MULTI-STATE BREACH: File '${finding.filePath}' was defined multiple times in the engine output.`);
      pipelineFailed = true;
    }

    // Inclusion (Reachable): if a file is a live risk, it must actively exist in the compiled asset graph.
    if (finding.status === 'REACHABLE' && !isAssetCompiled) {
      errorLog.push(`TELEMETRY GRAPH BREACH (Inclusion Failed): Engine flagged '${finding.filePath}' as REACHABLE but it is completely missing from the active build graphs.`);
      pipelineFailed = true;
    }

    // Exclusion (Muted): if flagged as dead code or tree-shaken, it cannot actively exist inside the compiled assets.
    if (finding.status === 'MUTED' && isAssetCompiled) {
      errorLog.push(`TELEMETRY GRAPH BREACH (Exclusion Failed): Engine flagged '${finding.filePath}' as MUTED/Dead-Code, but it actively exists inside the shipping compiled assets.`);
      pipelineFailed = true;
    }

    if (finding.status === 'WARNING') {
      warningLog.push(`Unresolved dynamic reference or wildcard evaluation found in: '${finding.filePath}'`);
    }

    engineFiles.add(normalisedPath);
    totalRecordsChecked++;
  }

  // Completeness reverse-audit: ensures the analysis engine didn't bypass any file actively bundled by the compilers.
  for (const compiledAsset of compiledAssetGraph) {
    // The audit target is restricted to the internal application source footprint
    if (compiledAsset.includes(path.join('packages', 'evershop', 'src')) && !engineFiles.has(compiledAsset)) {
      errorLog.push(`COMPLETENESS BREACH: The compiler bundled source file '${compiledAsset}', but the analysis engine completely bypassed evaluating it.`);
      pipelineFailed = true;
    }
  }

  // Evaluate statistical distribution
  if (totalRecordsChecked > 0 && counts.REACHABLE === 0 && counts.MUTED === 0) {
    errorLog.push(`TRIVIAL PAYLOAD BREACH: Engine failed statistical distribution check. Found REACHABLE: ${counts.REACHABLE}, MUTED: ${counts.MUTED}.`);
    pipelineFailed = true;
  }

  // Handle final reporting
  if (pipelineFailed) {
    console.error(`\n🚨 PHASE 2 FAILED: Invariant Matrix validation failed with ${errorLog.length} breach(es):`);
    errorLog.forEach((err, index) => {
      console.error(`  [${index + 1}] ${err}`);
    });
    console.error("\n❌ Pipeline terminated due to compilation telemetry alignment violations.");
    process.exit(1);
  }

  console.log("✅ PHASE 2 PASSED: Live graph intersection matches live compiler telemetry mapping.\n");

  if (warningLog.length > 0) {
    console.warn(`⚠️  ENGINE ALERT: Triage required for ${warningLog.length} unresolved dynamic/wildcard reference(s):`);
    warningLog.forEach((warn, index) => {
      console.warn(`  [${index + 1}] ${warn}`);
    });
    console.warn("");
  }

  console.log(`\nSUCCESS: Security pipeline logic safely validated across ${totalRecordsChecked} matrix records.`);
  process.exit(0);
}

runSafetyNet();