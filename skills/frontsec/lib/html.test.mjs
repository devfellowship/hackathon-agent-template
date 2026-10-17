import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as H from './html.mjs';

test('attrs and tags', () => {
  const t = H.findTags('<a HREF=x target="_blank" rel=\'nofollow noopener\' download>', 'a')[0];
  assert.deepEqual(t.attrs, { href: 'x', target: '_blank', rel: 'nofollow noopener', download: true });
});

test('blank links', () => {
  const line = '<a target="_blank" rel="nofollow">A</a> <a target="_blank" rel="NoReferrer">B</a> <a target="_blank">C</a> <a href=x>D</a>';
  assert.equal(H.unsafeBlankLinks(line).length, 2);
  assert.equal(H.unsafeBlankLinks('<a target="_BLANK">x</a>', { exactTarget: true }).length, 0);
});

test('scripts, schemes, inline, meta, sri', () => {
  const s = H.scriptSrcs('<script src="http://a.example/x.js"></script><script src="//cdn/x.js" integrity="sha384-abc="></script><script type=module src=/a.js></script>');
  assert.deepEqual(s.map((x) => x.scheme), ['http', 'protocol-relative', 'relative']);
  assert.equal(H.hasValidSri(s[1].integrity), true);
  assert.equal(H.urlHost('https://Cdn.X.example:443/a'), 'cdn.x.example');
  const html = '<html>\n<script>\nvar a=1;\n</script>\n<script src="a.js"></script>\n';
  assert.deepEqual(H.inlineScripts(html).map((x) => x.startLine), [2]);
  assert.equal(H.metaHttpEquiv('<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">')[0].httpEquiv, 'content-security-policy');
  assert.equal(H.inlineHandlers('<img src=x onerror="alert(1)">')[0].attr, 'onerror');
});
