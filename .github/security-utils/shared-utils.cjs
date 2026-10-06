const fs = require('fs');
const path = require('path');

/**
 * Safely reads and parses a JSON file with polymorphic tool context errors.
 */
function safeReadJson(filePath, toolContext = 'SYSTEM') {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    const prefix = toolContext.toUpperCase();
    console.error(`${prefix} ERROR: Failed to read or parse file at ${filePath}`);
    process.exit(1);
  }
}

/**
 * Strips script extensions from a full file path using native Node.js path structures.
 */
function stripExtension(filePath) {
  const parsed = path.parse(filePath);
  parsed.base = parsed.name;
  return path.format(parsed);
}

module.exports = {
  safeReadJson,
  stripExtension
};