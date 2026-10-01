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

  // Phase 1 structural validation passed if we made it here
  console.log("✅ PHASE 1 PASSED: Output matches required structural schema contract.");

  console.log("\n=== Phase 2: Differential graph matrix ===");
  if (!fs.existsSync('compilation-graph.json')) {
    console.error("🚨 PHASE 2 CRITICAL: 'compilation-graph.json' not found. Webpack stats are missing.");
    process.exit(1);
  }

  const webpackGraph = safeReadJson('compilation-graph.json');

  // Extract and normalise pathways compiled by Webpack
  const clientCompiledSet = new Set(
    (webpackGraph.modules || [])
      .map(m => m.name ? path.normalize(m.name).replace(/^.*node_modules[\\/]/, '') : null)
      .filter(Boolean)
  );

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
    const fileInWebpack = clientCompiledSet.has(normalisedPath);
    counts[finding.status] = (counts[finding.status] || 0) + 1;

    // Reachable files must be inside Webpack's compiled graph as invariant logic
    if (finding.status === 'REACHABLE' && !fileInWebpack) {
      errorLog.push(`LOGIC BREACH: Engine flagged '${finding.filePath}' as REACHABLE but it does not exist in Webpack.`);
      pipelineFailed = true;
    }

    // Muted files must not be inside Webpack's compiled graph as invariant logic
    if (finding.status === 'MUTED' && fileInWebpack) {
      errorLog.push(`LOGIC BREACH: Engine flagged '${finding.filePath}' as MUTED but Webpack actively compiled this file.`);
      pipelineFailed = true;
    }

    // Uniqueness check
    if (engineFiles.has(normalisedPath)) {
      errorLog.push(`MULTI-STATE BREACH: File '${finding.filePath}' was defined multiple times in the engine output.`);
      pipelineFailed = true;
    }

    if (finding.status === 'WARNING') {
      warningLog.push(`Unresolved dynamic reference or wildcard evaluation found in: '${finding.filePath}'`);
    }

    engineFiles.add(normalisedPath);
    totalRecordsChecked++;
  }

  // Accumulate completeness gaps
  for (const webpackModule of clientCompiledSet) {
    if (webpackModule.includes('packages/evershop/src') && !engineFiles.has(webpackModule)) {
      errorLog.push(`COMPLETENESS BREACH: Webpack compiled source file '${webpackModule}' but the engine skipped evaluating it.`);
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
    console.error(`🚨 PHASE 2 FAILED: Engine logic validation failed with ${errorLog.length} breach(es):`);
    errorLog.forEach((err, index) => {
      console.error(`  [${index + 1}] ${err}`);
    });
    console.error("\n❌ Pipeline terminated due to logic errors.");
    process.exit(1);
  }

  console.log("✅ PHASE 2 PASSED: Graph intersection matches live Webpack compilation telemetry.\n");

  if (warningLog.length > 0) {
    console.warn(`⚠️  ENGINE ALERT: Triage required for ${warningLog.length} unresolved dynamic/wildcard reference(s):`);
    warningLog.forEach((warn, index) => {
      console.warn(`  [${index + 1}] ${warn}`);
    });
    console.warn("");
  }

  console.log(`\n🎉 SUCCESS: Security pipeline logic safely validated across ${totalRecordsChecked} matrix records.`);
  process.exit(0);
}

runSafetyNet();