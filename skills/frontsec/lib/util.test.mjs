import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as U from './util.mjs';
import * as F from './files.mjs';
import * as D from './dates.mjs';
import { scanTree, bannersByFile } from './engine.mjs';

test('sort and text order', () => {
  assert.deepEqual(['sid', 'Auth', '__Host-x'].sort(U.txt), ['Auth', '__Host-x', 'sid']);
  const r = U.sortBy([{ p: 10, id: 'b' }, { p: 30, id: 'a' }, { p: 10, id: 'a' }], '-p', 'id');
  assert.deepEqual(r.map((x) => x.p + x.id), ['30a', '10a', '10b']);
  assert.deepEqual(U.sortBy([['g', 'x'], ['c', 'u', 'x'], ['a', 'x']], { get: (x) => x, cmp: U.cmpShortestThenText }), [['a', 'x'], ['g', 'x'], ['c', 'u', 'x']]);
  assert.deepEqual(['assets/b.js', 'index.html', 'headers.json'].sort(U.txt), ['assets/b.js', 'headers.json', 'index.html']);
});

test('grades and math', () => {
  const scale = [[0, 'A'], [15, 'B'], [35, 'C'], [59, 'D'], [Infinity, 'F']];
  assert.deepEqual([0, 15, 16, 59, 60].map((v) => U.scaleGrade(v, scale)), ['A', 'B', 'C', 'D', 'F']);
  assert.equal(U.scaleGrade(0, scale, { forced: 'F' }), 'F');
  assert.equal(U.floorDiv(25 * 10, 3), 83);
  assert.equal(U.maxByOrder(['media', 'alta', 'baixa'], ['baixa', 'media', 'alta', 'critica']), 'alta');
  assert.equal(U.firstMatch([[false, 'a'], [() => true, 'b']], 'z'), 'b');
  assert.equal(U.safe('x', () => { throw new Error('boom'); }, 7), 7);
});

test('dates', () => {
  assert.ok(D.isBefore('2026-10-19', '2026-10-20'));
  assert.ok(!D.isBefore('2026-10-20', '2026-10-20'));
  assert.equal(D.daysBetween('2026-10-20', '2026-10-27'), 7);
  assert.equal(D.addDays('2026-12-31', 1), '2027-01-01');
});

test('files and engine', () => {
  const root = mkdtempSync(join(tmpdir(), 'fs-'));
  mkdirSync(join(root, 'assets/vendor'), { recursive: true });
  writeFileSync(join(root, 'index.html'), '<p>\n<a target="_blank">x</a>\n');
  writeFileSync(join(root, 'assets/vendor/v.js'), '/*! lib@1.0.0 */debugger;debugger\n//# sourceMappingURL=../v.js.map');
  writeFileSync(join(root, 'assets/v.js.map'), '{}');
  writeFileSync(join(root, 'assets/x.css'), 'debugger');
  assert.deepEqual(F.walk(root), ['assets/v.js.map', 'assets/vendor/v.js', 'assets/x.css', 'index.html']);
  assert.equal(F.resolveFrom('assets/vendor/v.js', '../v.js.map'), 'assets/v.js.map');
  assert.equal(F.resolveFrom('a.js', '../../x'), null);
  assert.ok(F.existsIn(root, 'assets/v.js.map'));
  const { findings, hits } = scanTree(root, { rules: [
    { code: 'D', exts: ['.js'], detect: (l) => (l.match(/debugger/g) || []).map(() => ({})) },
    { code: 'B', exts: ['.html'], detect: (l) => l.includes('_blank') },
  ] });
  assert.deepEqual(findings, [{ rule: 'D', file: 'assets/vendor/v.js', line: 1 }, { rule: 'B', file: 'index.html', line: 2 }]);
  assert.equal(hits.length, 3);
  assert.deepEqual([...bannersByFile(root).keys()], ['assets/vendor/v.js']);
  assert.equal(F.lineOfIndex('a\nb\nc', 4), 3);
  assert.throws(() => F.writeOut('../x.json', {}));
});
