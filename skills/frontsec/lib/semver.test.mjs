import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cmpVersion, satisfies, smallestSafe, maxSatisfying, diffKind, sortVersions } from './semver.mjs';

test('numeric compare and prerelease', () => {
  assert.ok(cmpVersion('1.10.0', '1.9.0') > 0);
  assert.ok(cmpVersion('1.0.10', '1.0.9') > 0);
  assert.ok(cmpVersion('1.0.0-rc.1', '1.0.0') < 0);
  assert.ok(cmpVersion('1.0.0-alpha', '1.0.0-alpha.1') < 0);
  assert.ok(cmpVersion('1.0.0-alpha.2', '1.0.0-alpha.10') < 0);
  assert.ok(cmpVersion('1.0.0-beta', '1.0.0-alpha') > 0);
  assert.equal(cmpVersion('1.0.0+b1', '1.0.0'), 0);
  assert.deepEqual(sortVersions(['1.10.0', '1.2.0', '1.9.1']), ['1.2.0', '1.9.1', '1.10.0']);
});

test('plain comparators and ||', () => {
  assert.ok(satisfies('1.4.2', '>=1.0.0 <1.4.5'));
  assert.ok(!satisfies('1.4.5', '>=1.0.0 <1.4.5'));
  assert.ok(!satisfies('2.5.3', '<2.5.3 || >=3.0.0 <3.0.4'));
  assert.ok(satisfies('3.0.3', '<2.5.3 || >=3.0.0 <3.0.4'));
  assert.ok(satisfies('1.2.3', '1.2.3'));
  assert.ok(satisfies('1.2.3', '=1.2.3'));
  assert.ok(satisfies('1.2.3', '>= 1.2.0 < 2.0.0'));
});

test('caret, tilde, x, hyphen', () => {
  assert.ok(satisfies('1.9.9', '^1.2.0'));
  assert.ok(!satisfies('2.0.0', '^1.2.0'));
  assert.ok(!satisfies('0.3.0', '^0.2.1'));
  assert.ok(satisfies('0.2.9', '^0.2.1'));
  assert.ok(!satisfies('0.0.4', '^0.0.3'));
  assert.ok(satisfies('1.2.9', '~1.2.3'));
  assert.ok(!satisfies('1.3.0', '~1.2.3'));
  assert.ok(satisfies('1.9.0', '~1'));
  assert.ok(satisfies('1.2.9', '1.2.x'));
  assert.ok(!satisfies('1.3.0', '1.2.x'));
  assert.ok(satisfies('5.0.0', '*'));
  assert.ok(satisfies('5.0.0', ''));
  assert.ok(satisfies('2.3.4', '1.2.3 - 2.3.4'));
  assert.ok(!satisfies('2.3.5', '1.2.3 - 2.3.4'));
  assert.ok(satisfies('2.3.9', '1.2 - 2.3'));
  assert.ok(!satisfies('2.4.0', '1.2 - 2.3'));
  assert.ok(satisfies('2.0.0', '>1.x'));
  assert.ok(!satisfies('1.9.0', '>1.x'));
  assert.ok(satisfies('1.9.0', '<=1.x'));
  assert.ok(!satisfies('1.0.0', '<1.x'));
});

test('prerelease policies', () => {
  assert.ok(satisfies('1.5.0-beta', '>=1.0.0 <2.0.0'));
  assert.ok(!satisfies('1.5.0-beta', '>=1.0.0 <2.0.0', { npmPrerelease: true }));
  assert.ok(satisfies('1.5.0-beta.2', '>=1.5.0-beta.1 <2.0.0', { npmPrerelease: true }));
  assert.ok(!satisfies('2.0.0-rc.1', '^1.0.0'));
});

test('smallestSafe / maxSatisfying / diffKind', () => {
  assert.equal(smallestSafe(['1.4.2', '1.4.3', '1.4.5', '1.4.10'], '1.4.2', ['>=1.0.0 <1.4.5']), '1.4.5');
  assert.equal(smallestSafe(['1.0.0', '2.0.0'], '1.0.0', ['<3.0.0']), null);
  assert.equal(smallestSafe(['1.10.0', '1.9.0', '1.2.0'], '1.1.0', ['<1.2.0', '=1.9.0']), '1.2.0');
  assert.equal(smallestSafe(['1.2.0', '1.3.0'], '1.1.0', ['<1.2.1']), '1.3.0');
  assert.equal(maxSatisfying(['1.2.0', '1.10.0', '2.0.0'], '^1.0.0'), '1.10.0');
  assert.equal(diffKind('1.2.3', '2.0.0'), 'major');
  assert.equal(diffKind('1.2.3', '1.2.4'), 'patch');
});
