const path = require('path');

/**
 * Standardises a raw file path into a clean, environment-agnostic logical key.
 * Removes workspace prefixes (dist/src) and drops file extensions.
 * @param {string} filePath
 * @returns {string}
 */
function getLogicalModuleKey(filePath) {
  if (!filePath) return '';

  let cleanPath = path.normalize(filePath).replace(/\\/g, '/');

  cleanPath = cleanPath.replace(/^packages\/evershop\/(dist|src)\//, '');

  return cleanPath.replace(/\.[^/.]+\$/, '');
}

module.exports = {
  getLogicalModuleKey
};
