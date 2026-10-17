// File helpers: recursive walk with posix relative paths, line splitting, JSON IO, case listing.
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, posix } from 'node:path';

// All files under root (recursive), as POSIX paths relative to root, sorted by plain text order.
// opts.exts = ['.js', '.html'] keeps only those extensions (case-sensitive, exact suffix).
// ex: walk('casos/c1/dist', { exts: ['.js'] }) -> ['assets/a.js', 'assets/vendor/b.js']
export function walk(root, opts = {}) {
  const out = [];
  if (!existsSync(root)) return out;
  const rec = (rel) => {
    for (const name of readdirSync(rel ? join(root, rel) : root)) {
      const r = rel ? `${rel}/${name}` : name;
      if (statSync(join(root, r)).isDirectory()) rec(r);
      else out.push(r);
    }
  };
  rec('');
  const keep = opts.exts ? out.filter((f) => opts.exts.some((e) => f.endsWith(e))) : out;
  return keep.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

export const extOf = (file) => {
  const base = file.slice(file.lastIndexOf('/') + 1);
  const i = base.lastIndexOf('.');
  return i <= 0 ? '' : base.slice(i);
};

export const readText = (p) => readFileSync(p, 'utf8');
export const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
export const readJsonOr = (p, fallback) => (existsSync(p) ? readJson(p) : fallback);

// Split into lines by '\n'. Line numbers start at 1: lines[i] is line i+1.
// opts.stripCR removes a trailing '\r' (only if the spec does not say otherwise).
export function splitLines(text, opts = {}) {
  const lines = text.split('\n');
  return opts.stripCR ? lines.map((l) => l.replace(/\r$/, '')) : lines;
}

// Iterate lines: fn(line, lineNumber). ex: eachLine(text, (l, n) => ...)
export function eachLine(text, fn, opts) {
  splitLines(text, opts).forEach((l, i) => fn(l, i + 1));
}

// 1-based line number of a character index inside text.
export function lineOfIndex(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

// Resolve a relative reference (./x, ../x, x, /x) from a file's folder, inside a root.
// Returns the POSIX path relative to root, or null if it escapes the root.
// ex: resolveFrom('assets/js/a.js', '../maps/a.js.map') -> 'assets/maps/a.js.map'
// opts.rootAbsolute: a leading '/' means root-relative (default true).
export function resolveFrom(fromFile, ref, opts = {}) {
  const clean = ref.split('#')[0].split('?')[0];
  let p;
  if (clean.startsWith('/')) {
    if (opts.rootAbsolute === false) return null;
    p = posix.normalize(clean.slice(1));
  } else {
    p = posix.normalize(posix.join(posix.dirname(fromFile), clean));
  }
  if (p.startsWith('..') || p === '.') return null;
  return p;
}

// Does root/rel exist as a file? ex: existsIn('casos/c1/dist', 'assets/a.js.map')
export const existsIn = (root, rel) => rel !== null && existsSync(join(root, rel)) && statSync(join(root, rel)).isFile();

// Case folders = subfolders of casesDir, sorted. ex: listCases('casos') -> ['exemplo-1', ...]
export function listCases(casesDir = 'casos') {
  if (!existsSync(casesDir)) return [];
  return readdirSync(casesDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
}

// Write pretty JSON, creating the folder. Refuses any path outside out/.
export function writeOut(path, data) {
  const norm = posix.normalize(path.replace(/\\/g, '/'));
  if (!norm.startsWith('out/')) throw new Error(`refusing to write outside out/: ${path}`);
  mkdirSync(dirname(norm), { recursive: true });
  writeFileSync(norm, JSON.stringify(data, null, 2) + '\n');
}
