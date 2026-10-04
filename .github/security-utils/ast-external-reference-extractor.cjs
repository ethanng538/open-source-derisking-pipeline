const acorn = require('acorn');
const path = require('path');

function cleanQueryAndLoaders(rawString) {
  if (typeof rawString !== 'string' || !rawString) return '';
  let target = rawString.split('?')[0]; // Drops query variables
  if (target.includes('!')) { target = target.split('!').pop(); } // Drops loader syntax
  return target.trim();
}

function resolveLocalPath(currentFile, importString) {
  if (!importString || !importString.startsWith('.')) return null;
  const currentDir = path.dirname(currentFile);
  const absoluteTarget = path.resolve(currentDir, cleanQueryAndLoaders(importString));

  const extensionsToTry = ['', '.ts', '.tsx', '.js', '.jsx', '/index.ts', '/index.js'];
  for (const ext of extensionsToTry) {
    const pathWithExt = absoluteTarget + ext;
    if (require('fs').existsSync(pathWithExt) && require('fs').statSync(pathWithExt).isFile()) {
      return path.normalize(path.relative(process.cwd(), pathWithExt));
    }
  }
  return null;
}

/**
 * Parses raw code text via Acorn and extracts all string references.
 * Completely blind to audit data or vulnerability status.
 */
function extractFileMetadata(filePath, codeText) {
  const localLinks = new Set();
  const rawPackages = new Set();
  let isAmbiguous = false;

  try {
    const ast = acorn.parse(codeText, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowHashBang: true,
      allowReturnOutsideFunction: true
    });

    function walk(node) {
      if (!node || isAmbiguous) return;

      function processStringValue(val) {
        if (typeof val !== 'string' || !val) return;
        if (val.startsWith('.')) {
          const resolved = resolveLocalPath(filePath, val);
          if (resolved) localLinks.add(resolved);
        } else {
          rawPackages.add(cleanQueryAndLoaders(val));
        }
      }

      if (node.type === 'ImportDeclaration' && node.source) {
        if (node.source.type === 'Literal') processStringValue(node.source.value);
        else isAmbiguous = true;
      }

      if (node.type === 'ImportExpression') {
        if (node.source && node.source.type === 'Literal') processStringValue(node.source.value);
        else isAmbiguous = true;
      }

      if (node.type === 'CallExpression' && node.callee && node.callee.name === 'require') {
        const args = node.arguments;
        if (args && args.length > 0) {
          if (args[0].type === 'Literal') processStringValue(args[0].value);
          else isAmbiguous = true;
        }
      }

      if (node.type === 'Literal') processStringValue(node.value);

      if (node.type === 'TemplateLiteral' && node.quasis) {
        node.quasis.forEach(q => { if (q.value && q.value.cooked) processStringValue(q.value.cooked); });
      }

      for (const key in node) {
        if (node[key] && typeof node[key] === 'object') {
          if (Array.isArray(node[key])) node[key].forEach(walk);
          else walk(node[key]);
        }
      }
    }

    walk(ast);
  } catch (err) {
    isAmbiguous = true;
  }

  return {
    isAmbiguous,
    localLinks: Array.from(localLinks),
    rawPackages: Array.from(rawPackages)
  };
}

module.exports = { extractFileMetadata };