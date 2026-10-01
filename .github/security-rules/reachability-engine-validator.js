const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    console.error(`🚨 CRITICAL ERROR: Failed to read or parse file at ${filePath}`);
    process.exit(1);
  }
}

function runSafetyNet() {
  console.log("=== Phase 1: structural validation ===");
  if (!fs.existsSync('reachability-results.json')) {
    console.error("🚨 PHASE 1 FAILED: 'reachability-results.json' not found. Engine did not run.");
    process.exit(1);
  }

  const engineOutput = safeReadJson('reachability-results.json');
  if (!engineOutput.findings || !Array.isArray(engineOutput.findings)) {
    console.error("🚨 PHASE 1 FAILED: Engine payload is missing a valid 'findings' array.");
    process.exit(1);
  }

  console.log("=== Phase 2: differential graph matrix ===");
  const webpackGraph = safeReadJson('compilation-graph.json');

  // Extract normalized pathways compiled by Webpack
  const clientCompiledSet = new Set(
    (webpackGraph.modules || [])
      .map(m => m.name ? path.normalize(m.name).replace(/^.*node_modules[\\/]/, '') : null)
      .filter(Boolean)
  );

  const engineFiles = new Set();
  let totalRecordsChecked = 0;
  let counts = { REACHABLE: 0, MUTED: 0 };

  for (const finding of engineOutput.findings) {
    const normalizedPath = path.normalize(finding.filePath);
    const fileInWebpack = clientCompiledSet.has(normalizedPath);
    counts[finding.status] = (counts[finding.status] || 0) + 1;

    // Reachable files must be inside Webpack's compiled graph as invariant logic
    if (finding.status === 'REACHABLE' && !fileInWebpack) {
      console.error(`🚨 LOGIC BREACH: Engine flagged '${finding.filePath}' as REACHABLE but it does not exist in Webpack.`);
      process.exit(1);
    }

    // Muted files must not be inside Webpack's compiled graph as invariant logic
    if (finding.status === 'MUTED' && fileInWebpack) {
      console.error(`🚨 LOGIC BREACH: Engine flagged '${finding.filePath}' as MUTED but Webpack actively compiled this file.`);
      process.exit(1);
    }

    // Uniqueness bound: prevent dual states for the same file
    if (engineFiles.has(normalizedPath)) {
      console.error(`🚨 MULTI-STATE BREACH: File '${finding.filePath}' was defined multiple times.`);
      process.exit(1);
    }

    engineFiles.add(normalizedPath);
    totalRecordsChecked++;
  }

  // Completeness guardrail: ensure the engine did not drop source files Webpack tracked
  for (const webpackModule of clientCompiledSet) {
    if (webpackModule.includes('packages/evershop/src') && !engineFiles.has(webpackModule)) {
      console.error(`🚨 COMPLETENESS BREACH: Webpack compiled source file '${webpackModule}', but the engine skipped evaluating it.`);
      process.exit(1);
    }
  }

  // Distribution bound: prevent blank or fully monochrome flatline
  if (counts.REACHABLE === 0 || counts.MUTED === 0) {
    console.error(`🚨 TRIVIAL PAYLOAD BREACH: Engine failed statistical distribution check. Found REACHABLE: ${counts.REACHABLE}, MUTED: ${counts.MUTED}.`);
    process.exit(1);
  }

  console.log(`\n✅ SUCCESS: Security pipeline logic safely validated across ${totalRecordsChecked} matrix records.`);
  process.exit(0);
}

runSafetyNet();