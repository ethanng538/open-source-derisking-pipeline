export function findIndirectUsages(vulnerableFilesMap, fileGraph) {
  const tracePayload = new Map();
  const tracingQueue = [];

  vulnerableFilesMap.forEach((meta, filePath) => {
    const packagesArray = meta.package ? (Array.isArray(meta.package) ? meta.package : [meta.package]) : [];

    tracePayload.set(filePath, {
      status: meta.reason,
      viaOriginFiles: [],
      package: packagesArray,
      impactedBySymbols: [...meta.taintedExports],
      traceChains: [[filePath]]
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

    fileGraph.forEach((graphData, consumerFilePath) => {
      const consumerImportsMap = graphData.localImports;

      // Checks if the potential consumer file imports anything from the current vulnerable file
      if (consumerImportsMap && consumerImportsMap[currentPath]) {
        const importedSpecifiers = consumerImportsMap[currentPath];

        const matchesVulnerabilityTaint = importedSpecifiers.some(specifier =>
          activeTaintedExportsInFile.has(specifier) || activeTaintedExportsInFile.has('*')
        );

        if (matchesVulnerabilityTaint) {
          const existingRecord = tracePayload.get(consumerFilePath);
          const currentTaintedSymbols = importedSpecifiers.filter(s => activeTaintedExportsInFile.has(s));

          const currentParentRecord = tracePayload.get(currentPath);
          const primaryParentChain = currentParentRecord?.traceChains?.[0] || [currentPath];
          const extendedChain = [...primaryParentChain, consumerFilePath];

          // If it is the first time seeing this consumer file
          if (!existingRecord) {
            tracePayload.set(consumerFilePath, {
              status: 'INDIRECT_USAGE',
              viaOriginFiles: [rootOrigin],
              package: packageRef ? [packageRef] : [],
              impactedBySymbols: currentTaintedSymbols,
              traceChains: [extendedChain]
            });

            tracingQueue.push({
              currentPath: consumerFilePath,
              rootOrigin,
              packageRef,
              activeTaintedExportsInFile: activeTaintedExportsInFile
            });
          } else {
            // The file was already tainted by another vulnerability
            let structureChanged = false;

            // Merge unique origin files
            if (rootOrigin && !existingRecord.viaOriginFiles.includes(rootOrigin)) {
              existingRecord.viaOriginFiles.push(rootOrigin);
              structureChanged = true;
            }

            // Merge unique packages
            if (packageRef && !existingRecord.package.includes(packageRef)) {
              existingRecord.package.push(packageRef);
              structureChanged = true;
            }

            // Merge unique impacted symbols
            currentTaintedSymbols.forEach(symbol => {
              if (!existingRecord.impactedBySymbols.includes(symbol)) {
                existingRecord.impactedBySymbols.push(symbol);
                structureChanged = true;
              }
            });

            // Appends the new alternative trail to the trace chains log
            existingRecord.traceChains.push(extendedChain);

            if (structureChanged) {
              tracingQueue.push({
                currentPath: consumerFilePath,
                rootOrigin,
                packageRef,
                activeTaintedExportsInFile: activeTaintedExportsInFile
              });
            }
          }
        }
      }
    });
  }

  return tracePayload;
}