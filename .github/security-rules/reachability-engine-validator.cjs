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


function runResolverValidator() {
  let pipelineFailed = false;
  const errorLog = [];
  const warningLog = [];

  console.log("=== Phase 1: Structural validation ===");
  if (!fs.existsSync('reachability-results.json')) {
    console.error("PHASE 1 ERROR: 'reachability-results.json' not found. Reachability validator did not run.");
    process.exit(1);
  }

  const resolverOutput = safeReadJson('reachability-results.json');
  if (!resolverOutput.findings || !Array.isArray(resolverOutput.findings)) {
    console.error("PHASE 1 ERROR: Resolver results is missing a valid 'findings' array.");
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

  const resolverFiles = new Set();
  let totalRecordsChecked = 0;
  let counts = { SAFE: 0, REACHABLE: 0, MUTED: 0, AMBIGUOUS: 0 };

  for (const finding of resolverOutput.findings) {
    if (!finding.filePath || !finding.status) {
      errorLog.push(`Malformed record structure found at index ${totalRecordsChecked}`);
      pipelineFailed = true;
      totalRecordsChecked++;
      continue;
    }

    const normalisedPath = path.normalize(finding.filePath);
    const isAssetCompiled = compiledAssetGraph.has(normalisedPath);

    // Multi-state breach check
    if (resolverFiles.has(normalisedPath) && finding.status !== 'PENDING_EVALUATION') {
      errorLog.push(`MULTI-STATE BREACH: File '${finding.filePath}' was defined multiple times with conflicting explicit states.`);
      pipelineFailed = true;
    }

    if (resolverFiles.has(normalisedPath) && finding.status === 'PENDING_EVALUATION') {
      totalRecordsChecked++;
      continue;
    }

    let effectiveStatus = finding.status;
    if (finding.status === 'PENDING_EVALUATION') {
      effectiveStatus = isAssetCompiled ? 'REACHABLE' : 'MUTED';
    }

    counts[effectiveStatus] = (counts[effectiveStatus] || 0) + 1;

    // Inclusion (reachable): if a file is a live risk, it must actively exist in the compiled asset graph.
    if (effectiveStatus === 'REACHABLE' && !isAssetCompiled) {
      errorLog.push(`LOGIC BREACH: Engine flagged '${finding.filePath}' as REACHABLE but it is completely missing from the active build graphs.`);
      pipelineFailed = true;
    }

    resolverFiles.add(normalisedPath);
    totalRecordsChecked++;
  }

  const filesWithAmbiguousDependencies = webpackGraph.unresolvedDynamicImports || [];

  for (const warningFile of filesWithAmbiguousDependencies) {
    const normalisedWarnPath = path.normalize(warningFile);

    counts.AMBIGUOUS++;
    warningLog.push(`Unresolved dynamic reference or variable expression origin found in: '${warningFile}'`);

    resolverFiles.add(normalisedWarnPath);
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
      if (!resolverFiles.has(sourceAsset)) {
        errorLog.push(`COMPLETENESS BREACH: The compiler bundled custom source module '${sourceAsset}' but the resolver missed evaluating it.`);
        pipelineFailed = true;
      }
    }
  }

  // Evaluate statistical distribution
  if (totalRecordsChecked > 0 && counts.REACHABLE === 0 && counts.MUTED === 0 && counts.SAFE === 0) {
    errorLog.push(`TRIVIAL PAYLOAD BREACH: Engine failed statistical distribution check. Found REACHABLE: ${counts.REACHABLE}, MUTED: ${counts.MUTED}, SAFE: ${counts.SAFE}.`);
    pipelineFailed = true;
  }

  // Handle final reporting
  if (pipelineFailed) {
    console.error(`PHASE 2 ERROR: Invariant matrix validation failed with ${errorLog.length} breach(es):`);
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
    engineFilesSize: resolverFiles.size
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

  console.log(`📊 Validation summary`);
  console.log(`Total evaluated: ${totalRecordsChecked} target files`);
  console.log("---");
  console.log(`⚪ MUTED risks: ${counts.MUTED} (pruned or non-compiled code)`);
  console.log(`⚠️ WARNINGS: ${counts.AMBIGUOUS} (dynamic imports needing human audit)`);

  if (counts.REACHABLE > 0) {
    console.log(`🔴 REACHABLE risks:  ${counts.REACHABLE} (vulnerabilities built into binary)`);
    console.log("\nACTION RECOMMENDED:");
    console.log("Check 'reachability-results.json' to cross-reference the reachable");
    console.log("vulnerabilities and execute version updates to clear production threats.");
  } else {
    console.log(`🔵 REACHABLE risks: ${counts.REACHABLE} (zero live vulnerabilities deployed)`);
  }
  console.log(`\nSUCCESS: Security pipeline logic safely validated across ${totalRecordsChecked} records.`);
  process.exit(0);
}

runResolverValidator();