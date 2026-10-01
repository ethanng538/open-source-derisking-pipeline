import pkg from 'webpack';
import { error } from '../../lib/log/logger.js';
import { createConfigClient } from '../../lib/webpack/prod/createConfigClient.js';
import { createConfigServer } from '../../lib/webpack/prod/createConfigServer.js';

const { webpack } = pkg;

import fs from 'fs';
import path from 'path';

function runOne(config) {
  const compiler = webpack(config);
  return new Promise((resolve, reject) => {
    compiler.run((err, stats) => {

      if (stats && !stats.hasErrors()) {
        try {
          const statsJson = stats.toJson({ all: false, modules: true });
          const targetOutput = path.join(process.cwd(), 'compilation-graph.json');

          const compiledModules = (statsJson.modules || [])
            .filter(m => m.name)
            .map(m => ({ name: m.name }));

          let existingData = { modules: [] };
          if (fs.existsSync(targetOutput)) {
            try {
              existingData = JSON.parse(fs.readFileSync(targetOutput, 'utf8'));
            } catch (e) {
              // Silent fail
            }
          }

          const combined = [...(existingData.modules || []), ...compiledModules];
          const unique = Array.from(new Set(combined.map(m => m.name))).map(name => ({ name }));

          fs.writeFileSync(targetOutput, JSON.stringify({ modules: unique }, null, 2), 'utf8');
        } catch (dumpError) {
        }
      }


      // close() releases the compiler's resources (and flushes any persistent
      // cache). Resolve/reject from inside its callback so the compilation is
      // fully torn down — and collectable — before the next one starts.
      compiler.close(() => {
        if (err || stats.hasErrors()) {
          if (err) {
            error(err);
          }
          error(
            stats.toString({
              errorDetails: true,
              warnings: true
            })
          );
          reject(err);
          return;
        }
        resolve(stats);
      });
    });
  });
}

export async function compile(routes) {
  // Build the client and server compilations SEQUENTIALLY rather than as a
  // single concurrent MultiCompiler. Running them together keeps both module
  // graphs + every emitted asset resident in one V8 heap at once, pushing peak
  // memory past ~3.3GB and OOMing on small (4GB) hosts. Sequentially, the client
  // compilation becomes collectable before the server one peaks, so peak memory
  // is ~max(client, server) and the build fits within a ~2GB heap. (Wall time is
  // not worse — the concurrent run oversubscribed the CPU during minification.)
  // See specifications/store-front-architecture-audit.md.
  await runOne(createConfigClient(routes));
  // Hint V8 to reclaim the client compilation before the server build allocates.
  // No-op unless started with --expose-gc; on memory-limited hosts the default
  // heap cap already forces this collection under pressure.
  if (global.gc) {
    global.gc();
  }
  return runOne(createConfigServer(routes));
}
