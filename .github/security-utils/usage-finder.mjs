export function findTransitiveUsages(infectedFilesMap, completeFileGraph) {
  const completeTracePayload = new Map();
  const tracingQueue = [];

  infectedFilesMap.forEach((meta, filePath) => {
    completeTracePayload.set(filePath, {
      status: meta.reason,
      ...(meta.package ? { package: meta.package } : {}),
      taintedExports: meta.taintedExports,
      traceChain: [filePath]
    });

    tracingQueue.push({
      currentPath: filePath,
      rootOrigin: filePath,
      packageRef: meta.package,
      activeTaintedExportsInFile: new Set(meta.taintedExports)
    });
  });

  // Trace references outward to consumer routes
  while (tracingQueue.length > 0) {
    const { currentPath, rootOrigin, packageRef, activeTaintedExportsInFile } = tracingQueue.shift();

    // Scan every file in the compilation context to find who imports our current target
    completeFileGraph.forEach((graphData, consumerFilePath) => {
      const consumerImportsMap = graphData.localImports; // dependencies -> [specifiers]

      if (consumerImportsMap && consumerImportsMap[currentPath]) {
        const importedSpecifiers = consumerImportsMap[currentPath];

        // ISOLATION CRITERIA: Check if consumer uses any of the tainted exports
        // If a file imports a wild-card, or the dependency root is ambiguous, mark it as infected.
        const matchesVulnerabilityTaint = importedSpecifiers.some(specifier =>
          activeTaintedExportsInFile.has(specifier) || activeTaintedExportsInFile.has('*')
        );

        if (matchesVulnerabilityTaint && !completeTracePayload.has(consumerFilePath)) {
          const inheritedChain = [...completeTracePayload.get(currentPath).traceChain, consumerFilePath];

          // The consumer file inherits vulnerability exposure only because it touched an infected component name
          completeTracePayload.set(consumerFilePath, {
            status: 'TRANSITIVE_USAGE',
            viaOriginFile: rootOrigin,
            ...(packageRef ? { package: packageRef } : {}),
            impactedBySymbols: importedSpecifiers.filter(s => activeTaintedExportsInFile.has(s)),
            traceChain: inheritedChain
          });

          // Enqueue consumer to trace items importing it further downstream
          tracingQueue.push({
            currentPath: consumerFilePath,
            rootOrigin,
            packageRef,
            activeTaintedExportsInFile: new Set(graphData.taintedExports)
          });
        }
      }
    });
  }

  return completeTracePayload;
}