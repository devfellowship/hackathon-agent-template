import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as X from './headers.mjs';

test('case-insensitive headers', () => {
  assert.equal(X.getHeader({ 'strict-transport-security': 'max-age=1' }, 'Strict-Transport-Security'), 'max-age=1');
  assert.equal(X.getHeader({ A: '1' }, 'b'), undefined);
});

test('CSP', () => {
  const c = X.parseCsp("default-src *; Script-Src 'self' https://*.cdn.example; script-src 'unsafe-inline'");
  const e = X.effectiveDirective(c, ['script-src', 'default-src']);
  assert.equal(e.name, 'script-src');
  assert.deepEqual(X.unsafeTokens(e.values), []);
  assert.ok(X.hasWildcardHost(e.values));
  const d = X.effectiveDirective(X.parseCsp("img-src *; default-src 'self' 'unsafe-eval'"), ['script-src', 'default-src']);
  assert.deepEqual(X.unsafeTokens(d.values), ["'unsafe-eval'"]);
  assert.equal(X.effectiveDirective(X.parseCsp('img-src *'), ['script-src', 'default-src']), null);
  assert.ok(X.hasNonceOrHash(["'nonce-abc'"]));
});

test('HSTS and others', () => {
  assert.equal(X.parseHsts('max-age=31536000; includeSubDomains').maxAge, 31536000);
  assert.equal(X.parseHsts('MAX-AGE="10"; preload').preload, true);
  assert.equal(X.parseHsts('includeSubDomains').maxAge, null);
  assert.equal(X.parseHsts(undefined).present, false);
  assert.equal(X.framingProtection({ 'X-Frame-Options': 'SAMEORIGIN' }).protected, true);
  assert.equal(X.framingProtection({ 'Content-Security-Policy': "frame-ancestors 'none'" }).protected, true);
  assert.equal(X.nosniffOk({ 'x-content-type-options': 'nosniff' }), true);
  assert.equal(X.referrerPolicy({ 'Referrer-Policy': 'no-referrer, unsafe-url' }).unsafe, true);
  assert.deepEqual(X.parsePermissionsPolicy('camera=(), geolocation=(self "https://a")'), { camera: [], geolocation: ['self', '"https://a"'] });
  assert.equal(X.corsInfo({ 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }).wildcardWithCredentials, true);
});
