import path from 'node:path';

export function stripExtension(filePath) {
  const parsed = path.parse(filePath);
  parsed.base = parsed.name;
  return path.format(parsed);
}

export function cleanQueryAndLoaders(rawString) {
  if (typeof rawString !== 'string' || !rawString) return '';
  let target = rawString.split('?')[0];
  if (target.includes('!')) { target = target.split('!').pop(); }
  return target.trim();
}