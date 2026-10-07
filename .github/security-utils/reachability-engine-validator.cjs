const fs = require('fs');
const path = require('path');

const { safeReadJson, stripExtension } = require('./shared-utils.cjs');


function runResolverValidator() {
  let pipelineFailed = false;
  const errorLog = [];
  const warningLog = [];

  console.log("=== Validating reachability results ===\n");

  console.log(">>> Phase 1: structural validation");

  if (!fs.existsSync('dependency-vulnerabilities.json')) {
    console.error("PHASE 1 ERROR: 'dependency-vulnerabilities.json' not found. Potential vulnerability results is missing.");
    process.exit(1);
  }

  // Just files found to be not safe by the resolver
  if (!fs.existsSync('reachability-results.json')) {
    console.error("PHASE 1 ERROR: 'reachability-results.json' not found. Reachability validator did not run.");
    process.exit(1);
  }

  // All files evaluated by the resolver
  if (!fs.existsSync('resolver-evaluation-record.json')) {
    console.error("PHASE 1 ERROR: 'resolver-evaluation-record.json' not found. Resolver records are not available.");
    process.exit(1);
  }

  const finderOutput = safeReadJson('dependency-vulnerabilities.json');
  const reachabilityOutput = safeReadJson('reachability-results.json');
  const reachabilityEvaluationRecord = safeReadJson('resolver-evaluation-record.json');

  if (!finderOutput.findings || !Array.isArray(finderOutput.findings)) {
    console.error("PHASE 1 ERROR: Finder results is missing a valid 'findings' array.");
    process.exit(1);
  }

  if (!reachabilityOutput.findings || !Array.isArray(reachabilityOutput.findings)) {
    console.error("PHASE 1 ERROR: Resolver results is missing a valid 'findings' array.");
    process.exit(1);
  }

  if (
    !reachabilityEvaluationRecord.records || !Array.isArray(reachabilityEvaluationRecord.records) ||
    !reachabilityEvaluationRecord.evaluations || !Array.isArray(reachabilityEvaluationRecord.evaluations)
  ) {
    console.error("PHASE 1 ERROR: Resolver record is missing a valid 'records' or 'evaluations' array.");
    process.exit(1);
  }

  console.log("✅ PHASE 1 PASSED: Output matches required structural schema contract.\n");

  console.log(">>> Phase 2: reachability verification");
  const graphPath = process.env.COMPILATION_GRAPH_PATH || 'compilation-graph.json';

  if (!fs.existsSync(graphPath)) {
    console.error(`PHASE 2 ERROR: '${graphPath}' not found. Compiler telemetry graph is missing.`);
    process.exit(1);
  }

  const webpackGraph = safeReadJson(graphPath);

  const compiledAssetGraph = new Set([
    ...(webpackGraph.frontend || []),
    ...(webpackGraph.backend || [])
  ].map(p => {
    const normalised = path.normalize(p);
    const sourceAligned = normalised.replace(/[\\/]dist[\\/]/, '/src/');
    return stripExtension(sourceAligned);
  }));

  // The intersection between the compilation graph and files with potential vulnerabilities
  const pendingFinderFiles = new Set(
    (finderOutput.findings)
      .filter(f => f.status === 'PENDING_EVALUATION')
      .map(f => stripExtension(path.normalize(f.filePath)))
  );
  const validatorSearchSpace = new Set(
    (webpackGraph.appSource)
      .map(p => stripExtension(path.normalize(p)))
      .filter(p => pendingFinderFiles.has(p))
  );

  const searchSpacePayload = {
    generatedAt: new Date().toISOString(),
    totalSuspectModulesTracked: validatorSearchSpace.size,
    searchSpacePaths: Array.from(validatorSearchSpace).sort()
  };

  fs.writeFileSync(
    path.join(process.cwd(), 'validator-search-space.json'),
    JSON.stringify(searchSpacePayload, null, 2),
    'utf8'
  );

  const evaluatedFiles = new Set(
    (reachabilityEvaluationRecord.records).map(p => stripExtension(path.normalize(p)))
  );
  const resolverEvaluations = (reachabilityEvaluationRecord.evaluations).map(e => ({
    filePath: stripExtension(path.normalize(e.filePath)),
    status: e.status
  }));

  // Used to check for duplicate entries
  const processedResolverFiles = new Set();

  let totalRecordsChecked = 0;
  let counts = { SAFE: 0, REACHABLE: 0, MUTED: 0, AMBIGUOUS: 0 };

  for (let i = 0; i < resolverEvaluations.length; i++) {
    const evaluation = resolverEvaluations[i];

    if (!evaluation.filePath || !evaluation.status) {
      errorLog.push(`Malformed record structure found at index ${i}`);
      pipelineFailed = true;
      continue;
    }

    const targetPath = evaluation.filePath;
    const isAssetCompiled = compiledAssetGraph.has(targetPath);

    // Multi-state breach check
    if (processedResolverFiles.has(targetPath)) {
      errorLog.push(`MULTI-STATE BREACH: File '${targetPath}' was defined multiple times with conflicting explicit states.`);
      pipelineFailed = true;
    }
    processedResolverFiles.add(targetPath);

    if (evaluation.status === 'PENDING_EVALUATION') {
      errorLog.push(`UNASSIGNED EVALUATION BREACH: File '${targetPath}' was passed through without being resolved to SAFE, REACHABLE or MUTED.`);
      pipelineFailed = true;
      continue;
    }

    const effectiveStatus = evaluation.status;
    if (counts.hasOwnProperty(effectiveStatus)) {
      counts[effectiveStatus]++;
    }

    // Inclusion (reachable): if a file is a live risk, it must actively exist in the compiled asset graph.
    if (effectiveStatus === 'REACHABLE' && !isAssetCompiled) {
      errorLog.push(`LOGIC BREACH: Resolver flagged '${targetPath}' as REACHABLE but it is missing from the active build graphs.`);
      pipelineFailed = true;
    }

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
      errorLog.push(`ZERO RECORD BREACH: The resolver evaluated 0 files but 'npm-audit.json' contains ${totalAuditVulnerabilities} active vulnerabilities.`);
      pipelineFailed = true;
    } else {
      console.log(" Zero records found because the project package manifest has 0 vulnerabilities.");
    }
  }

  // Completeness reverse-audit: ensures the reachability resolver didn't miss any file actively bundled by the compiler
  for (const sourceAsset of validatorSearchSpace) {
    if (!evaluatedFiles.has(sourceAsset)) {
      errorLog.push(`COMPLETENESS BREACH: The compiler bundled vulnerable suspect module '${sourceAsset}' but the reachability resolver missed evaluating it.`);
      pipelineFailed = true;
    }
  }

  const filesWithAmbiguousDependencies = webpackGraph.unresolvedDynamicImports;

  for (const warningFile of filesWithAmbiguousDependencies) {
    const normalisedWarnPath = path.normalize(warningFile);

    if (!evaluatedFiles.has(normalisedWarnPath)) {
      errorLog.push(`COMPLETENESS BREACH: The compiler detected an unresolved dynamic import in '${normalisedWarnPath}' but the reachability resolver missed evaluating it.`);
      pipelineFailed = true;
      continue;
    }

    warningLog.push(`Unresolved dynamic reference or variable expression origin found in: '${normalisedWarnPath}'`);
  }

  // Evaluate statistical distribution
  if (totalRecordsChecked > 0 && counts.SAFE === 0 && counts.REACHABLE === 0 && counts.MUTED === 0 && counts.AMBIGUOUS === 0) {
    errorLog.push(`TRIVIAL PAYLOAD BREACH: Resolver failed statistical distribution check. Found REACHABLE: ${counts.REACHABLE}, MUTED: ${counts.MUTED}, SAFE: ${counts.SAFE}.`);
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
    validatorSearchSpaceSize: validatorSearchSpace.size,
    resolverRecordsSize: evaluatedFiles.size
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