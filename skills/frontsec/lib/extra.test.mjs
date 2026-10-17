import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as L from './index.mjs';

test('word boundary tokens, placeholders, PEM, url creds', () => {
  const re = L.tokenRegex('k_', 'a-z0-9', 4, 4, { boundary: 'word' });
  assert.equal(L.matchAll('"k_ab12"', re).length, 1);
  assert.equal(L.matchAll('k_ab12A', re).length, 0);
  assert.equal(L.matchAll('xk_ab12', re).length, 0);
  assert.ok(L.allSameChar('xxxx'));
  const pem = L.findPemBlocks(['a', '-----BEGIN RSA PRIVATE KEY-----', ' AB ', 'CD', '-----END RSA PRIVATE KEY-----', '-----BEGIN PUBLIC KEY-----']);
  assert.deepEqual(pem, [{ beginLine: 2, endLine: 5, body: 'ABCD' }]);
  assert.deepEqual(L.findUrlCredentials('x="https://u:p@h/"; y="http://a@b"').map((c) => c.userinfo), ['u:p']);
});

test('taint tracking and listeners', () => {
  const t = L.taintTracker({ sources: ['location.hash'], sanitizers: ['encodeURIComponent('] });
  const a = L.parseVarAssignment('const q = location.hash.slice(1);');
  t.assign(a.name, a.expr);
  assert.ok(t.isTainted('el.innerHTML = q'));
  assert.ok(!t.isTainted('x.q'));
  assert.ok(!t.isTainted('encodeURIComponent(q)'));
  t.assign('q', '"ok"');
  assert.ok(!t.isTainted('q'));
  assert.equal(L.parseVarAssignment('if (a == b) x()'), null);
  assert.equal(L.parseVarAssignment('a += 1'), null);
  assert.equal(L.sinkSegments('location.href = q; x', [L.REDIRECT_SINKS.locationHref])[0].segment, ' q');
  const ls = L.findMessageListeners(["addEventListener('message', function (e) {", '  go(e.data);', '});', 'addEventListener("message", m => {', 'if (m.origin.endsWith(x)) y()', '})']);
  assert.deepEqual(ls.map((l) => [l.line, l.param, l.endLine, l.checksOrigin]), [[1, 'e', 3, false], [4, 'm', 6, false]]);
});

test('browser jar: reject, replace keeps position, delete, send order', () => {
  const jar = L.createJar({ publicSuffixes: ['example'] });
  const r = jar.receive('https://loja.shop.example/conta/entrar', '2026-10-20T13:00:00Z', [
    'sid=1; Path=/; Secure', 'c=1', 'bad=1; Domain=example', 'x=1; Domain=api.shop.example', 'n=1; SameSite=None', 'p=1; Domain=.shop.example; Path=/conta; Max-Age=60',
  ]);
  assert.deepEqual(r.map((x) => x.reason || x.action), ['set', 'set', 'public_suffix', 'domain_mismatch', 'samesite_none_insecure', 'set']);
  jar.receive('https://loja.shop.example/', '2026-10-20T13:00:10Z', ['sid=2; Path=/; Secure']);
  const send = jar.cookiesFor('https://loja.shop.example/conta/x', { context: 'same-site' });
  assert.equal(L.cookieHeader(send), 'c=1; p=1; sid=2');
  assert.equal(L.cookieHeader(jar.cookiesFor('https://api.shop.example/conta', { context: 'cross-site', navigation: true, method: 'GET' })), 'p=1');
  assert.equal(L.cookieHeader(jar.cookiesFor('https://api.shop.example/conta', { context: 'cross-site', method: 'POST' })), '');
  jar.expire('2026-10-20T13:01:00Z');
  assert.deepEqual(jar.list().map((e) => e.name), ['sid', 'c']);
  assert.equal(L.isoNoMs(Date.parse('2026-10-20T13:01:00.000Z')), '2026-10-20T13:01:00Z');
  assert.deepEqual(L.parseUrl('http://A.b/x/?q=1'), { scheme: 'http', host: 'a.b', path: '/x/', query: 'q=1' });
});

test('headers: referrer list, csp policies; util countKeys', () => {
  assert.equal(L.referrerPolicy([['Referrer-Policy', 'unsafe-url'], ['referrer-policy', 'no-referrer, bogus']]).policy, 'no-referrer');
  assert.equal(L.referrerPolicy({}).policy, 'strict-origin-when-cross-origin');
  assert.equal(L.cspPolicies([['CSP', 'x'], ['Content-Security-Policy', "script-src 'self'"], ['content-security-policy-report-only', 'y']]).length, 1);
  assert.deepEqual(L.countKeys([{ t: 'a' }, { t: 'a' }], (x) => x.t, ['a', 'b']), { a: 2, b: 0 });
});

test('deps: per copy, skip dev, declared range', () => {
  const lock = { lockfileVersion: 3, packages: { '': { dependencies: { a: '^1' }, devDependencies: { t: '1' } }, 'node_modules/a': { version: '1.0.0', dependencies: { x: '^1.0.0' } }, 'node_modules/x': { version: '1.0.0' }, 'node_modules/a/node_modules/x': { version: '1.0.0' }, 'node_modules/t': { version: '1.0.0', dev: true, dependencies: { x: '*' } } } };
  const adv = [{ id: 'A', pkg: 'x', range: '<1.1.0', severity: 'high' }];
  assert.equal(L.auditDeps({ lock, advisories: adv }).length, 1);
  assert.deepEqual(L.auditDeps({ lock, advisories: adv, perCopy: true }).map((d) => d.id), ['node_modules/a/node_modules/x', 'node_modules/x']);
  const g = L.buildGraph(lock, { skipDev: true, rootFields: ['dependencies'] });
  assert.deepEqual(L.directDependents(g, 'node_modules/x'), []);
  assert.deepEqual(L.directDependents(g, 'node_modules/a/node_modules/x'), ['node_modules/a']);
  assert.equal(L.declaredRange(g, 'node_modules/a', 'x'), '^1.0.0');
});

test('engine alarm on always-firing rule and directDependents(lock)', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const root = mkdtempSync(join(tmpdir(), 'al-'));
  writeFileSync(join(root, 'a.js'), Array.from({ length: 20 }, (_, i) => `x${i}`).join('\n'));
  const errs = [];
  const orig = console.error;
  console.error = (m) => errs.push(m);
  const r = L.scanTree(root, { rules: [{ code: 'BAD', detect: (l) => (l.includes('zzz') ? [{}] : []) || [{}] }, { code: 'OOPS', detect: (l) => [] && [{}] }] });
  console.error = orig;
  assert.equal(r.stats.OOPS.hitLines, 20);
  assert.ok(errs.some((e) => e.includes('rule OOPS')));
  const lock = { lockfileVersion: 3, packages: { '': { dependencies: { a: '1' } }, 'node_modules/a': { version: '1.0.0', dependencies: { b: '1' } }, 'node_modules/b': { version: '1.0.0' } } };
  assert.deepEqual(L.directDependents(lock, 'node_modules/b'), ['node_modules/a']);
  assert.deepEqual(L.directDependents(lock, 'node_modules/a'), ['']);
});

test('rule factories always return arrays', () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const tok = `eyJhbGciOiJIUzI1NiJ9.${b64({ role: 'admin' })}.c2ln`;
  assert.deepEqual(L.ruleJwt('J', (p) => p?.role !== 'anon').detect(`a="${tok}"`).map((h) => h.cred), [tok]);
  assert.deepEqual(L.ruleJwt('J', (p) => p?.role !== 'anon').detect('nothing'), []);
  assert.equal(L.ruleSecret('S', [L.tokenRegex('k_', 'a-z', 3)]).detect('k_abc k_ab').length, 1);
  assert.equal(L.ruleScriptSrc('H', (s) => s.startsWith('http://')).detect('<script src="http://x/a.js"></script>').length, 1);
  assert.equal(L.ruleStorageKey('T', ['token']).detect("localStorage.setItem('Auth_Token', v)").length, 1);
  assert.deepEqual(L.ruleSourceMap('M', '/nonexistent').detect('//# sourceMappingURL=data:x', { file: 'a.js' }).length, 1);
  assert.deepEqual(L.ruleRegex('R', /debugger/g).detect('x'), []);
});
