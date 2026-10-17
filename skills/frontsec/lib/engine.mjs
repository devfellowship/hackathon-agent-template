// Line-rule engine: run many detectors over every line of every file in a tree, dedupe, keep raw hits.
import { join } from 'node:path';
import { extOf, readText, splitLines, walk } from './files.mjs';
import { findBanners } from './scan.mjs';
import { txt } from './util.mjs';

// scanTree(root, { rules, exts, stripCR })
//   rules: [{ code, exts: ['.js', '.html'], detect(line, ctx) }]
//     detect returns: false/0/null/[] (nothing) | true (1 hit) | array of hits (objects, e.g. { cred: 'the-secret' })
//     ctx = { file (posix, relative to root), lineNo (1-based), ext, root, lines (all lines of the file) }
//   exts: which files are read at all (default ['.js', '.html']; 'all' = every file of any extension).
// Returns {
//   findings: unique { rule, file, line } (one per rule+file+line), sorted file(text) -> line(num) -> rule(text)
//   hits: every raw hit { rule, file, line, ...hitObject } (use for "group by credential" etc.)
//   files: list of files read
// }
// ex: scanTree('casos/c1/dist', { rules: [{ code: 'R1', exts: ['.js'], detect: (l) => l.includes('debugger') }] })
export function scanTree(root, opts = {}) {
  const exts = opts.exts || ['.js', '.html'];
  const rules = opts.rules || [];
  const files = walk(root, exts === 'all' ? {} : { exts });
  const hits = [];
  const seen = new Map();
  for (const file of files) {
    const ext = extOf(file);
    const lines = splitLines(readText(join(root, file)), { stripCR: opts.stripCR });
    lines.forEach((line, i) => {
      const ctx = { file, lineNo: i + 1, ext, root, lines };
      for (const r of rules) {
        if (r.exts && !r.exts.includes(ext)) continue;
        const res = r.detect(line, ctx);
        const arr = res === true ? [{}] : Array.isArray(res) ? res : typeof res === 'number' && res > 0 ? Array.from({ length: res }, () => ({})) : [];
        for (const h of arr) {
          const hit = { rule: r.code, file, line: i + 1, ...(h && typeof h === 'object' ? h : {}) };
          hits.push(hit);
          const k = `${r.code}\u0000${file}\u0000${i + 1}`;
          if (!seen.has(k)) seen.set(k, { rule: r.code, file, line: i + 1 });
        }
      }
    });
  }
  const findings = [...seen.values()].sort((a, b) => txt(a.file, b.file) || a.line - b.line || txt(a.rule, b.rule));
  return { findings, hits, files };
}

// Banners per file: Map file -> [{ name, version, id }]. Only files with the given extensions (default .js).
// ex: const bmap = bannersByFile(dist); const ids = new Set([...bmap.values()].flat().map((b) => b.id))
export function bannersByFile(root, opts = {}) {
  const m = new Map();
  for (const file of walk(root, { exts: opts.exts || ['.js'] })) {
    const bs = findBanners(readText(join(root, file)), opts);
    if (bs.length) m.set(file, bs);
  }
  return m;
}
