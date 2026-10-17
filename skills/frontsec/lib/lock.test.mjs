import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nameOf, parentKey, resolveDep, resolveTree, normalizeLock } from './lock.mjs';
import { auditDeps } from './deps.mjs';

const lock = { lockfileVersion: 3, packages: {
  '': { dependencies: { a: '^1', z: '^1' }, devDependencies: { t: '^1' } },
  'node_modules/a': { version: '1.0.0', dependencies: { b: '^1' } },
  'node_modules/a/node_modules/b': { version: '1.0.0', dependencies: { c: '^1' } },
  'node_modules/c': { version: '2.0.0', dependencies: { a: '^1' } },
  'node_modules/a/node_modules/c': { version: '1.0.0' },
  'node_modules/z': { version: '1.0.0', dependencies: { c: '*' } },
  'node_modules/t': { version: '1.0.0', dependencies: { '@s/x': '*' } },
  'node_modules/@s/x': { version: '0.1.0' },
} };

test('names and resolution', () => {
  assert.equal(nameOf('node_modules/a/node_modules/@s/b'), '@s/b');
  assert.equal(parentKey('node_modules/a/node_modules/b'), 'node_modules/a');
  assert.equal(resolveDep(lock.packages, 'node_modules/a/node_modules/b', 'c'), 'node_modules/a/node_modules/c');
  assert.equal(resolveDep(lock.packages, 'node_modules/z', 'c'), 'node_modules/c');
  assert.equal(resolveDep(lock.packages, 'node_modules/z', 'nope'), null);
});

test('shortest paths with cycle and dev-only flag', () => {
  const t = resolveTree(lock);
  assert.deepEqual(t.get('node_modules/a/node_modules/c').path, ['a', 'b', 'c']);
  assert.deepEqual(t.get('node_modules/c').path, ['z', 'c']);
  assert.deepEqual(t.get('node_modules/@s/x').path, ['t', '@s/x']);
  assert.equal(t.get('node_modules/@s/x').viaDevOnly, true);
  assert.equal(t.get('node_modules/c').viaDevOnly, false);
  assert.equal(t.unreachable.length, 0);
});

test('tie-break by text order', () => {
  const l = { packages: { '': { dependencies: { m: '1', g: '1' } }, 'node_modules/m': { version: '1.0.0', dependencies: { x: '1' } }, 'node_modules/g': { version: '1.0.0', dependencies: { x: '1' } }, 'node_modules/x': { version: '1.0.0' } } };
  assert.deepEqual(resolveTree(l).get('node_modules/x').path, ['g', 'x']);
});

test('lockfile v1 conversion', () => {
  const v1 = { name: 'p', lockfileVersion: 1, dependencies: { a: { version: '1.0.0', requires: { b: '^1' }, dependencies: { b: { version: '1.1.0' } } }, b: { version: '2.0.0', dev: true } } };
  const n = normalizeLock(v1);
  assert.equal(n.packages['node_modules/a/node_modules/b'].version, '1.1.0');
  assert.deepEqual(Object.keys(n.packages[''].devDependencies), ['b']);
  assert.deepEqual(resolveTree(v1).get('node_modules/a/node_modules/b').path, ['a', 'b']);
});

test('auditDeps merges copies, fix and bundle', () => {
  const adv = [{ id: 'X-2', pkg: 'c', range: '<2.0.1', severity: 'high' }, { id: 'X-1', pkg: 'c', range: '>=1.0.0 <1.0.5', severity: 'low' }];
  const r = auditDeps({ lock, advisories: adv, versions: { c: ['1.0.0', '1.0.5', '2.0.0', '2.0.1', '2.1.0'] }, severityOrder: ['low', 'high'], bundleIds: new Set(['c@2.0.0']) });
  assert.deepEqual(r.map((d) => d.id), ['c@1.0.0', 'c@2.0.0']);
  assert.deepEqual(r[0].advisoryIds, ['X-1', 'X-2']);
  assert.equal(r[0].severity, 'high');
  assert.equal(r[0].fix, '2.0.1');
  assert.equal(r[1].inBundle, true);
  assert.equal(r[0].inBundle, false);
});
