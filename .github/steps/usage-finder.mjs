export function findIndirectUsages(infectedFilesMap, completeFileGraph) {
  const tracePayload = new Map();
  const tracingQueue = [];

  infectedFilesMap.forEach((meta, filePath) => {
    tracePayload.set(filePath, {
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

  while (tracingQueue.length > 0) {
    const { currentPath, rootOrigin, packageRef, activeTaintedExportsInFile } = tracingQueue.shift();

    completeFileGraph.forEach((graphData, consumerFilePath) => {
      const consumerImportsMap = graphData.localImports;

      if (consumerImportsMap && consumerImportsMap[currentPath]) {
        const importedSpecifiers = consumerImportsMap[currentPath];

        const matchesVulnerabilityTaint = importedSpecifiers.some(specifier =>
          activeTaintedExportsInFile.has(specifier) || activeTaintedExportsInFile.has('*')
        );

        if (matchesVulnerabilityTaint && !tracePayload.has(consumerFilePath)) {
          const inheritedChain = [...tracePayload.get(currentPath).traceChain, consumerFilePath];

          // The consumer file inherits vulnerability exposure only because it touched an infected component name
          tracePayload.set(consumerFilePath, {
            status: 'INDIRECT_USAGE',
            viaOriginFile: rootOrigin,
            ...(packageRef ? { package: packageRef } : {}),
            impactedBySymbols: importedSpecifiers.filter(s => activeTaintedExportsInFile.has(s)),
            traceChain: inheritedChain
          });

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

  return tracePayload;
}