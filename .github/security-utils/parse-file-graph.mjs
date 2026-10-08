import _traverse from '@babel/traverse';
import fs from 'node:fs';
import path from 'node:path';
import * as parser from '@babel/parser';

import { cleanQueryAndLoaders } from './path-utils.mjs';

const traverse = _traverse.default || _traverse;

function getBasePackage(cleanImportString) {
  if (!cleanImportString) return null;
  const parts = cleanImportString.split('/');
  return cleanImportString.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}


export function parseFileGraph(filePath, codeText, vulnerablePackagesSet) {
  const localImportsMap = new Map();
  const taintedExports = new Set();  // Exported names that touch the vulnerability
  const packageUsages = new Set();   // External packages actively used in this file
  let isAmbiguous = false;

  try {
    const ast = parser.parse(codeText, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript', 'decorators-legacy', 'classProperties'],
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true
    });

    const importedBindings = new Map();

    traverse(ast, {
      ImportDeclaration(fileImportPath) {
        const rawSource = fileImportPath.node.source.value;
        const cleanSource = cleanQueryAndLoaders(rawSource);

        const isAlias = cleanSource.startsWith('@components') || cleanSource.startsWith('@evershop');
        const isLocal = cleanSource.startsWith('.');

        let resolvedTarget = cleanSource;

        if (isLocal) {
          const currentDir = path.dirname(filePath);
          const absoluteTarget = path.resolve(currentDir, cleanSource);
          const extensions = ['', '.ts', '.tsx', '.js', '.jsx', '/index.ts', '/index.js'];
          resolvedTarget = null;
          for (const ext of extensions) {
            const fullPath = absoluteTarget + ext;
            if (fs.existsSync(fullPath) && fs.statSync(fullPath).isFile()) {
              resolvedTarget = path.normalize(path.relative(process.cwd(), fullPath));
              break;
            }
          }
          if (!resolvedTarget) return;
        } else if (!isAlias) {
          resolvedTarget = getBasePackage(cleanSource);
        }

        fileImportPath.node.specifiers.forEach(spec => {
          const localName = spec.local.name;
          const originalName = spec.type === 'ImportSpecifier' ? spec.imported.name : 'default';

          importedBindings.set(localName, {
            source: resolvedTarget,
            type: isLocal ? 'local' : 'package',
            originalName
          });
        });
      },

      CallExpression(fileImportPath) {
        if (fileImportPath.node.callee.name === 'require') {
          const arg = fileImportPath.node.arguments[0];
          if (arg && arg.type === 'StringLiteral') {
            const cleanSource = cleanQueryAndLoaders(arg.value);
            if (cleanSource.startsWith('.')) return;

            const basePkg = getBasePackage(cleanSource);
            const parentDecl = fileImportPath.findParent(p => p.isVariableDeclarator());

            if (parentDecl) {
              const idNode = parentDecl.node.id;
              if (idNode.type === 'Identifier') {
                importedBindings.set(idNode.name, { source: basePkg, type: 'package', originalName: 'default' });
              } else if (idNode.type === 'ObjectPattern') {
                idNode.properties.forEach(prop => {
                  if (prop.value && prop.value.type === 'Identifier') {
                    importedBindings.set(prop.value.name, { source: basePkg, type: 'package', originalName: prop.key.name });
                  }
                });
              }
            }
          } else {
            isAmbiguous = true;
          }
        }
      }
    });

    const activeTaintedLocalBindings = new Set();

    traverse(ast, {
      Identifier(idPath) {
        const name = idPath.node.name;
        if (importedBindings.has(name)) {
          const bindingInfo = importedBindings.get(name);

          if (bindingInfo.type === 'package' && vulnerablePackagesSet.has(bindingInfo.source)) {
            if (idPath.isReferencedIdentifier() || (idPath.parent && idPath.parent.type === 'MemberExpression' && idPath.parent.object === idPath.node)) {
              packageUsages.add(bindingInfo.source);
              activeTaintedLocalBindings.add(name);

              let parentFunc = idPath.findParent(p => p.isFunctionDeclaration() || p.isVariableDeclarator() || p.isClassDeclaration());
              if (parentFunc) {
                let componentName = null;
                if (parentFunc.isFunctionDeclaration() && parentFunc.node.id) componentName = parentFunc.node.id.name;
                else if (parentFunc.isVariableDeclarator() && parentFunc.node.id.type === 'Identifier') componentName = parentFunc.node.id.name;
                else if (parentFunc.isClassDeclaration() && parentFunc.node.id) componentName = parentFunc.node.id.name;

                if (componentName) {
                  activeTaintedLocalBindings.add(componentName);
                }
              }
            }
          }
        }
      },

      // Maps exactly which exports expose tainted components
      ExportNamedDeclaration(exportPath) {
        if (exportPath.node.declaration) {
          const decl = exportPath.node.declaration;
          if (decl.id && activeTaintedLocalBindings.has(decl.id.name)) {
            taintedExports.add(decl.id.name);
          } else if (decl.declarations) {
            decl.declarations.forEach(d => {
              if (d.id.type === 'Identifier' && activeTaintedLocalBindings.has(d.id.name)) {
                taintedExports.add(d.id.name);
              }
            });
          }
        }
        if (exportPath.node.specifiers) {
          exportPath.node.specifiers.forEach(spec => {
            if (activeTaintedLocalBindings.has(spec.local.name)) {
              taintedExports.add(spec.exported.name);
            }
          });
        }
      },

      ExportDefaultDeclaration(exportPath) {
        const decl = exportPath.node.declaration;
        if (decl.type === 'Identifier' && activeTaintedLocalBindings.has(decl.name)) {
          taintedExports.add('default');
        } else if (decl.type === 'FunctionDeclaration' && decl.id && activeTaintedLocalBindings.has(decl.id.name)) {
          taintedExports.add('default');
        } else if (exportPath.isReferenced()) {
          taintedExports.add('default');
        }
      }
    });

    importedBindings.forEach((binding, localName) => {
      if (binding.type === 'local') {
        if (!localImportsMap.has(binding.source)) {
          localImportsMap.set(binding.source, new Set());
        }
        localImportsMap.get(binding.source).add(binding.originalName);
      }
    });

  } catch (err) {
    console.error(`[Parser error in ${filePath}]:`, err);
    isAmbiguous = true;
  }

  const structuredLocalImports = {};
  localImportsMap.forEach((specifiers, filePathKey) => {
    structuredLocalImports[filePathKey] = Array.from(specifiers);
  });

  return {
    isAmbiguous,
    packageUsages: Array.from(packageUsages),
    taintedExports: Array.from(taintedExports),
    localImports: structuredLocalImports
  };
}