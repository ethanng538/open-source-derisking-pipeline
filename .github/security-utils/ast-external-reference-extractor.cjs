const acorn = require('acorn');
const jsx = require('acorn-jsx');
const JSXParser = acorn.Parser.extend(jsx());
const path = require('path');

function cleanQueryAndLoaders(rawString) {
  if (typeof rawString !== 'string' || !rawString) return '';
  let target = rawString.split('?')[0];
  if (target.includes('!')) { target = target.split('!').pop(); }
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

function extractFileMetadata(filePath, codeText) {
  const localLinks = new Set();
  const rawPackages = new Set();
  const usedIdentifiers = new Set();
  const importBindings = new Map();
  let isAmbiguous = false;

  try {
    const ast = JSXParser.parse(codeText, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      allowHashBang: true,
      allowReturnOutsideFunction: true
    });

    function walk(node) {
      if (!node || isAmbiguous) return;

      function processStringValue(val) {
        if (typeof val !== 'string' || !val) return '';
        const cleanVal = cleanQueryAndLoaders(val);
        if (cleanVal.startsWith('.')) {
          const resolved = resolveLocalPath(filePath, cleanVal);
          if (resolved) {
            localLinks.add(resolved);
            return resolved;
          }
        } else {
          rawPackages.add(cleanVal);
          return cleanVal;
        }
        return '';
      }

      if (node.type === 'ImportDeclaration' && node.source) {
        if (node.source.type === 'Literal') {
          const resolvedString = processStringValue(node.source.value);
          if (resolvedString && node.specifiers) {
            node.specifiers.forEach(spec => {
              if (spec.local && spec.local.name) {
                importBindings.set(spec.local.name, resolvedString);
              }
            });
          }
        } else isAmbiguous = true;
      }

      if (node.type === 'ImportExpression') {
        if (node.source && node.source.type === 'Literal') processStringValue(node.source.value);
        else isAmbiguous = true;
      }

      if (node.type === 'CallExpression' && node.callee && node.callee.name === 'require') {
        const args = node.arguments;
        if (args && args.length > 0) {
          if (args[0].type === 'Literal') {
            const resolvedString = processStringValue(args[0].value);
            if (resolvedString && node.parent && node.parent.type === 'VariableDeclarator' && node.parent.id.type === 'Identifier') {
              importBindings.set(node.parent.id.name, resolvedString);
            }
          } else isAmbiguous = true;
        }
      }

      if (node.type === 'Identifier') {
        const parentType = node.parent && node.parent.type;

        const isImportDeclaration =
          parentType === 'ImportSpecifier' ||
          parentType === 'ImportDefaultSpecifier' ||
          parentType === 'ImportNamespaceSpecifier';

        const isObjectKeyOrProperty =
          (parentType === 'Property' && node.parent.key === node && !node.parent.shorthand) ||
          (parentType === 'MemberExpression' && node.parent.property === node && !node.parent.computed);

        if (!isImportDeclaration && !isObjectKeyOrProperty) {
          usedIdentifiers.add(node.name);
        }
      }

      if (node.type === 'Literal') processStringValue(node.value);

      if (node.type === 'TemplateLiteral' && node.quasis) {
        node.quasis.forEach(q => { if (q.value && q.value.cooked) processStringValue(q.value.cooked); });
      }

      for (const key in node) {
        if (node[key] && typeof node[key] === 'object') {
          if (!Array.isArray(node[key])) node[key].parent = node;

          if (Array.isArray(node[key])) {
            node[key].forEach(subNode => {
              if (subNode && typeof subNode === 'object') subNode.parent = node;
              walk(subNode);
            });
          } else {
            walk(node[key]);
          }
        }
      }
    }

    walk(ast);
  } catch (err) {
    const importRegex = /(?:import\s+(?:[\w\s{},*]+|(?:\*\s+as\s+\w+))\s+from\s+['"]([^'"]+)['"])|(?:require\s*\(\s*['"]([^'"]+)['"]\s*\))/g;
    let match;
    let foundReferences = false;

    while ((match = importRegex.exec(codeText)) !== null) {
      foundReferences = true;
      const val = match[1] || match[2];
      if (val.startsWith('.')) {
        const resolved = resolveLocalPath(filePath, val);
        if (resolved) localLinks.add(resolved);
      } else {
        rawPackages.add(cleanQueryAndLoaders(val));
      }
    }
    isAmbiguous = !foundReferences && codeText.includes('import');
  }

  const activeImports = new Set();
  importBindings.forEach((importString, variableName) => {
    if (usedIdentifiers.has(variableName)) {
      activeImports.add(importString);
    }
  });

  importBindings.forEach((importString, variableName) => {
    if (!activeImports.has(importString)) {
      rawPackages.delete(importString);
      localLinks.delete(importString);
    }
  });

  return {
    isAmbiguous,
    localLinks: Array.from(localLinks),
    rawPackages: Array.from(rawPackages)
  };
}

module.exports = { extractFileMetadata };