import pkg from 'webpack';
import { error } from '../../lib/log/logger.js';
import { createConfigClient } from '../../lib/webpack/prod/createConfigClient.js';
import { createConfigServer } from '../../lib/webpack/prod/createConfigServer.js';

const { webpack } = pkg;

import fs from 'fs';
import path from 'path';

function runOne(config) {


  const forcedConfig = {
    ...config,
    stats: config.stats || { errorDetails: true, warnings: true }
  };


  const compiler = webpack(forcedConfig);


  console.log(`\n🔍 [${compiler.options.name}] Resolved infrastructure targets:`, compiler.options.target);


  return new Promise((resolve, reject) => {
    compiler.run((err, stats) => {


      const hasErrors = err || (stats && stats.hasErrors());

      compiler.close(() => {
        if (hasErrors) {
          if (err) error(err);
          if (stats) error(stats.toString());
          reject(err || new Error('Webpack compilation failed.'));
          return;
        }

        let compiledModules = [];
        let dynamicWarnings = [];

        try {
          const uniqueDiskPaths = new Set();

          const rawModules = stats.compilation.modules || [];
          const rawWarnings = stats.compilation.warnings || [];

          rawModules.forEach(mod => {
            const originalSources = mod.sourceMap?.sources;

            if (originalSources && originalSources.length > 0) {
              originalSources.forEach(sourcePath => {
                if (mod.resource) {
                  const absoluteSrcPath = path.resolve(path.dirname(mod.resource), sourcePath);
                  uniqueDiskPaths.add(absoluteSrcPath);
                }
              });
              return;
            }

            if (!mod.resource && mod.modules && Array.isArray(mod.modules)) {
              mod.modules.forEach(subMod => {
                if (subMod.resource) uniqueDiskPaths.add(subMod.resource);
              });
              return;
            }

            if (mod.resource) {
              uniqueDiskPaths.add(mod.resource);
            }
          });

          rawWarnings.forEach(warn => {
            if (warn.message && warn.message.includes('Critical dependency: the request of a dependency is an expression')) {
              let ambiguousFileOrigin = "Unknown Origin Context";

              if (warn.module && warn.module.resource) {
                ambiguousFileOrigin = path.normalize(path.relative(process.cwd(), warn.module.resource));
              }

              dynamicWarnings.push(ambiguousFileOrigin);
            }
          });

          compiledModules = Array.from(uniqueDiskPaths)
            .map(rawPath => {
              return path.normalize(path.relative(process.cwd(), rawPath));
            });

        } catch (dumpError) {
          error(`Telemetry compilation graph parsing error: ${dumpError.stack || dumpError}`);
        }

        resolve({ stats, compiledModules, dynamicWarnings });
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


  const clientResult = await runOne(createConfigClient(routes));


  // Hint V8 to reclaim the client compilation before the server build allocates.
  // No-op unless started with --expose-gc; on memory-limited hosts the default
  // heap cap already forces this collection under pressure.
  if (global.gc) {
    global.gc();
  }


  const serverResult = await runOne(createConfigServer(routes));

  const allBundledPaths = new Set([
    ...clientResult.compiledModules,
    ...serverResult.compiledModules
  ]);

  const finalGraph = {
    frontend: Array.from(new Set(clientResult.compiledModules)),
    backend: Array.from(new Set(serverResult.compiledModules)),
    appSource: Array.from(allBundledPaths).filter(p =>
      p.includes(path.join('packages', 'evershop', 'src')) ||
      p.includes(path.join('extensions'))
    ),
    unresolvedDynamicImports: Array.from(new Set([
      ...clientResult.dynamicWarnings,
      ...serverResult.dynamicWarnings
    ]))
  };

  const targetOutput = process.env.COMPILATION_GRAPH_PATH
    ? path.resolve(process.env.COMPILATION_GRAPH_PATH)
    : path.join(process.cwd(), 'compilation-graph.json');

  const targetDir = path.dirname(targetOutput);
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  fs.writeFileSync(targetOutput, JSON.stringify(finalGraph, null, 2), 'utf8');

  return serverResult.stats;
}