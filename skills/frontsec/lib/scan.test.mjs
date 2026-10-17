import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as S from './scan.mjs';

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (p) => `eyJhbGciOiJIUzI1NiJ9.${b64(p)}.c2ln`;

test('tokenRegex lengths and boundaries', () => {
  const live = S.tokenRegex('k_live_', 'A-Za-z0-9', 24);
  assert.equal(S.matchAll('x="k_live_' + 'a'.repeat(23) + '"', live).length, 0);
  assert.equal(S.matchAll('k_live_' + 'a'.repeat(30), live)[0].text.length, 37);
  assert.equal(S.matchAll('k_live_SUA_CHAVE_AQUI', live).length, 0);
  const hex = S.tokenRegex('h_', '0-9a-f', 32, 32, { boundary: 'right' });
  assert.equal(S.matchAll('h_' + 'a'.repeat(33), hex).length, 0);
  assert.equal(S.matchAll('h_' + 'a'.repeat(32) + '"', hex).length, 1);
  assert.equal(S.matchAll('h_' + 'a'.repeat(31) + 'G', hex).length, 0);
});

test('calls and first argument', () => {
  assert.equal(S.findCalls('window.eval(x)', 'eval').length, 1);
  assert.equal(S.findCalls('$eval(x); retrieval(y)', 'eval').length, 0);
  assert.equal(S.findCalls('new  Function(a)', 'new Function').length, 1);
  const a = S.firstArg('f( "a,b", c)', 2);
  assert.equal(a.isStringLiteral, true);
  assert.equal(a.literal, 'a,b');
  assert.equal(S.firstArg('f(`x`)', 2).isTemplate, true);
  assert.equal(S.firstArg('f()', 2).isEmpty, true);
});

test('dynamic code', () => {
  assert.equal(S.findDynamicCode('eval("1+1")').length, 0);
  assert.equal(S.findDynamicCode("eval( '1')").length, 0);
  assert.equal(S.findDynamicCode('eval(`1`)').length, 1);
  assert.equal(S.findDynamicCode('eval(code); new Function(body)').length, 2);
  assert.equal(S.findStringTimers('setTimeout("go()", 1); setTimeout(fn, 2)').length, 1);
});

test('sinks with sources', () => {
  const src = ['location.hash', 'event.data'];
  assert.equal(S.findSinkWithSource('d.innerHTML = location.hash;', { sources: src }).length, 1);
  assert.equal(S.findSinkWithSource('d.innerHTML += "<b>" + event.data.t', { sources: src }).length, 1);
  assert.equal(S.findSinkWithSource('if (d.innerHTML == location.hash) x()', { sources: src }).length, 0);
  assert.equal(S.findSinkWithSource('d.innerHTML = q; y(location.hash)', { sources: src }).length, 0);
  assert.equal(S.findSinkWithSource('d.innerHTML = e.data', { sources: src }).length, 0);
  assert.equal(S.findSinkWithSource('d.insertAdjacentHTML("beforeend", location.hash)', { sources: src }).length, 1);
  assert.equal(S.findSinkWithSource('document.write(location.hash);d.outerHTML=event.data', { sources: src }).length, 2);
});

test('storage keys', () => {
  const r = S.findStorageSets("localStorage.setItem('auth_TOKEN', v); localStorage.setItem(k, v); sessionStorage.setItem('token', 1)");
  assert.deepEqual(r.map((x) => x.key), ['auth_TOKEN', null]);
  assert.ok(S.containsAnyCI('SESSAO_ID', ['sessao']));
});

test('banners, source maps', () => {
  assert.deepEqual(S.findBanners('/*! datas-br@1.4.2 | MIT */x/*! @s/ui@2.0.0-rc.1 */').map((b) => b.id), ['datas-br@1.4.2', '@s/ui@2.0.0-rc.1']);
  assert.deepEqual(S.findSourceMapRef('x;//# sourceMappingURL=app.js.map'), { target: 'app.js.map', isDataUri: false, index: 2 });
  assert.equal(S.findSourceMapRef('//# sourceMappingURL=data:application/json;base64,eyJ9').isDataUri, true);
  assert.equal(S.findSourceMapRef('/*# sourceMappingURL=a.css.map */').target, 'a.css.map');
});

test('JWT decode', () => {
  const t = jwt({ role: 'admin', sub: 'x' });
  assert.equal(S.decodeJwt(t).payload.role, 'admin');
  const f = S.findJwts(`const k="${t}";`);
  assert.equal(f.length, 1);
  assert.equal(f[0].token, t);
  assert.equal(S.findJwts(`"${jwt({ sub: 1 })}"`)[0].payload.role, undefined);
  assert.equal(S.findJwts('eyJhbGc.bm90LWpzb24.sig')[0].payload, null);
  assert.equal(S.b64urlDecode('eyJhIjoiYj8_In0'), '{"a":"b??"}');
});
