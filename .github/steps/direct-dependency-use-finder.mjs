import fs from 'node:fs';
import path from 'node:path';

import { parseFileGraph } from '../security-utils/parse-file-graph.mjs';

export function findDirectUsages(appFiles, vulnerablePackagesSet) {
  const vulnerableFilesMap = new Map();
  const fileGraph = new Map();

  appFiles.forEach(file => {
    const code = fs.readFileSync(file, 'utf8');
    const relativeFile = path.normalize(path.relative(process.cwd(), file));
    const metadata = parseFileGraph(relativeFile, code, vulnerablePackagesSet);

    fileGraph.set(relativeFile, {
      localImports: metadata.localImports,
      taintedExports: metadata.taintedExports
    });

    if (metadata.isAmbiguous) {
      vulnerableFilesMap.set(relativeFile, { reason: 'AMBIGUOUS', taintedExports: ['UNKNOWN'] });
    } else if (metadata.packageUsages.length > 0) {
      vulnerableFilesMap.set(relativeFile, {
        reason: 'DIRECT_USAGE',
        package: metadata.packageUsages,
        taintedExports: metadata.taintedExports
      });
    }
  });

  return { vulnerableFilesMap, fileGraph };
}