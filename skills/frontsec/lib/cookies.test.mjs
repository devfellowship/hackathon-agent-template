import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as C from './cookies.mjs';

test('parse attributes, case-insensitive, last wins', () => {
  const c = C.parseSetCookie('sid=a=b; path=/x; SECURE; HttpOnly; samesite=none; Path=/y');
  assert.equal(c.name, 'sid');
  assert.equal(c.value, 'a=b');
  assert.equal(C.attrValue(c, 'path'), '/y');
  assert.ok(C.hasAttr(c, 'secure'));
  assert.equal(C.sameSite(c), 'none');
  assert.equal(C.sameSite(C.parseSetCookie('a=1'), { missing: 'lax' }), 'lax');
});

test('default path', () => {
  assert.equal(C.defaultPath('/api/login'), '/api');
  assert.equal(C.defaultPath('/entrar'), '/');
  assert.equal(C.defaultPath('/api/v1/auth/sair'), '/api/v1/auth');
  assert.equal(C.defaultPath('/a/b/?x=/c'), '/a/b');
  assert.equal(C.defaultPath(''), '/');
  assert.equal(C.cookiePath(C.parseSetCookie('a=1; Path=relative'), '/x/y'), '/x');
});

test('domain and lifetime', () => {
  assert.deepEqual(C.cookieDomain(C.parseSetCookie('a=1; Domain=.SHOP.example'), 'app.shop.example'), { domain: 'shop.example', hostOnly: false });
  assert.ok(C.domainMatches('app.shop.example', 'shop.example'));
  assert.ok(!C.domainMatches('app.shop.example', 'op.example'));
  const now = '2026-10-21T18:01:00Z';
  assert.equal(C.lifetime(C.parseSetCookie('a=1; Expires=Sun, 20 Dec 2026 18:01:00 GMT; Max-Age=3600'), now).lifetime, 3600);
  assert.equal(C.lifetime(C.parseSetCookie('a=1; Expires=Wed, 28 Oct 2026 18:01:00 GMT'), now).lifetime, 604800);
  assert.equal(C.lifetime(C.parseSetCookie('a=1; Max-Age=abc; Expires=Wed, 21 Oct 2026 18:00:00 GMT'), now).lifetime, -60);
  assert.equal(C.lifetime(C.parseSetCookie('a=1'), now).lifetime, null);
  assert.ok(Number.isFinite(C.parseHttpDate('Wed, 21-Oct-2026 07:28:00 GMT')));
});

test('prefixes', () => {
  assert.equal(C.prefixViolation(C.parseSetCookie('__Secure-a=1; Path=/')), 'secure-prefix-without-secure');
  assert.equal(C.prefixViolation(C.parseSetCookie('__Host-a=1; Secure')), 'host-prefix-path-not-root');
  assert.equal(C.prefixViolation(C.parseSetCookie('__Host-a=1; Secure; Path=/; Domain=x.example')), 'host-prefix-with-domain');
  assert.equal(C.prefixViolation(C.parseSetCookie('__Host-a=1; Secure; Path=/')), null);
  assert.equal(C.prefixViolation(C.parseSetCookie('__host-a=1')), null);
  assert.notEqual(C.prefixViolation(C.parseSetCookie('__host-a=1'), { ci: true }), null);
});

test('jar: identities, deletions, logout', () => {
  const steps = [
    { name: 'login', path: '/api/login', time: '2026-10-20T13:00:00Z', setCookies: ['sid=1; Secure', 't=1; Path=/; Max-Age=100', 'x=1; Path=/'] },
    { name: 'logout', path: '/api/logout', time: '2026-10-20T14:00:00Z', setCookies: ['sid=; Max-Age=0', 't=; Path=/api; Max-Age=0', 'x=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT', 'ghost=; Max-Age=0', 'new=1'] },
  ];
  const { identities, orphanDeletions } = C.runJar(steps, 'app.example');
  const get = (n) => [...identities.values()].find((r) => r.name === n);
  assert.equal(get('sid').path, '/api');
  assert.ok(C.deletedInStep(get('sid'), 1));
  assert.ok(!C.deletedInStep(get('t'), 1));
  assert.ok(C.deletedInStep(get('x'), 1));
  assert.ok(!C.setBefore(get('new'), 1));
  assert.equal(get('ghost'), undefined);
  assert.equal(orphanDeletions.length, 2);
});
