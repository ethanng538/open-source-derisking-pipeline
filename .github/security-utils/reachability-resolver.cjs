const fs = require('fs');
const path = require('path');

function safeReadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (err) {
    console.error(`🚨 RESOLVER ERROR: Cannot read ${filePath}`);
    process.exit(1);
  }
}

function runResolutionEngine() {
  console.log("Resolving files with reachable dependency vulnerabilities...");

  const rawFindingsPath = 'vulnerable-dependencies.json';
  const graphPath = process.env.COMPILATION_GRAPH_PATH || 'compilation-graph.json';

  if (!fs.existsSync(rawFindingsPath) || !fs.existsSync(graphPath)) {
    console.error(`RESOLVER ERROR: Missing input matrices (${rawFindingsPath} or ${graphPath})`);
    process.exit(1);
  }

  const rawFinderOutput = safeReadJson(rawFindingsPath);
  const webpackGraph = safeReadJson(graphPath);

  const compiledAssetGraph = new Set([
    ...(webpackGraph.frontend || []),
    ...(webpackGraph.backend || [])
  ].map(p => path.normalize(p)));

  const thirdPartyReachable = [];
  const appSourceContributors = new Set();

  // Evaluate raw targets
  for (const finding of rawFinderOutput.findings) {
    const normalisedPath = path.normalize(finding.filePath);
    const isAssetCompiled = compiledAssetGraph.has(normalisedPath);

    if (isAssetCompiled) {
      thirdPartyReachable.push(finding.filePath);

      if (webpackGraph.appSource && Array.isArray(webpackGraph.appSource)) {
        webpackGraph.appSource.forEach(srcFile => appSourceContributors.add(srcFile));
      }
    }
  }

  const structuredOutput = {
    generatedAt: new Date().toISOString(),
    findings: {
      thirdParty: thirdPartyReachable,
      appSource: Array.from(appSourceContributors)
    }
  };

  fs.writeFileSync('reachability-results.json', JSON.stringify(structuredOutput, null, 2), 'utf8');
  console.log(`✅ Mapping complete. Extracted ${thirdPartyReachable.length} live risks linked to application source.`);
}

runResolutionEngine();