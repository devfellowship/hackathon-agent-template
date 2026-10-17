// Light HTML helpers (regex based, line-friendly): tags with attributes, inline scripts, rel tokens, SRI.

// Parse an attribute string: name="v" | name='v' | name=v | name. Names lower-cased.
// Returns { attrs: {name: value|true}, list: [{ name, value, quoted }] } — the FIRST occurrence wins in attrs (HTML rule).
export function parseAttrs(s) {
  const list = [];
  const re = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const m of s.matchAll(re)) {
    const name = m[1].toLowerCase();
    const value = m[2] ?? m[3] ?? m[4];
    list.push({ name, value: value === undefined ? true : value, quoted: m[2] !== undefined ? '"' : m[3] !== undefined ? "'" : null });
  }
  const attrs = {};
  for (const a of list) if (!(a.name in attrs)) attrs[a.name] = a.value;
  return { attrs, list };
}

// Find opening tags <name ...> in a text (one line or a whole file). Tag name case-insensitive.
// Returns [{ tag, attrs, list, raw, index, end }]. ex: findTags(line, 'a').filter((t) => t.attrs.target === '_blank')
export function findTags(text, name) {
  const re = new RegExp(`<${name}(?=[\\s>/])([^>]*)>`, 'gi');
  const out = [];
  for (const m of text.matchAll(re)) {
    const { attrs, list } = parseAttrs(m[1]);
    out.push({ tag: name.toLowerCase(), attrs, list, raw: m[0], index: m.index, end: m.index + m[0].length });
  }
  return out;
}

// Space-separated tokens of an attribute (e.g. rel), lower-cased. ex: relTokens('nofollow NoOpener') -> ['nofollow','noopener']
export const relTokens = (v) => (typeof v === 'string' ? v.trim().toLowerCase().split(/\s+/).filter(Boolean) : []);

// <a target="_blank"> without noopener/noreferrer. opts.exactTarget: compare target exactly (default case-insensitive).
// opts.needs: rel words that make it safe (default ['noopener','noreferrer'] — any one is enough).
export function unsafeBlankLinks(text, opts = {}) {
  const needs = opts.needs || ['noopener', 'noreferrer'];
  return findTags(text, 'a').filter((t) => {
    const tgt = t.attrs.target;
    if (typeof tgt !== 'string') return false;
    if (opts.exactTarget ? tgt !== '_blank' : tgt.toLowerCase() !== '_blank') return false;
    const words = relTokens(t.attrs.rel);
    return !needs.some((w) => words.includes(w));
  });
}

// <script src=...> tags. Each gets { src, scheme: 'http'|'https'|'protocol-relative'|'relative'|'data'|other, integrity, crossorigin }.
export function scriptSrcs(text) {
  return findTags(text, 'script').filter((t) => typeof t.attrs.src === 'string').map((t) => ({
    ...t,
    src: t.attrs.src,
    scheme: urlScheme(t.attrs.src),
    integrity: typeof t.attrs.integrity === 'string' ? t.attrs.integrity : null,
    crossorigin: t.attrs.crossorigin ?? null,
  }));
}

// Classify a URL. ex: urlScheme('http://x') === 'http'; urlScheme('//cdn') === 'protocol-relative'; urlScheme('/a.js') === 'relative'
export function urlScheme(url) {
  const u = url.trim();
  if (u.startsWith('//')) return 'protocol-relative';
  const m = u.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  return m ? m[1].toLowerCase() : 'relative';
}

// Host of an absolute or protocol-relative URL (lower-case), else null.
export function urlHost(url) {
  const m = url.trim().match(/^(?:[a-zA-Z][a-zA-Z0-9+.-]*:)?\/\/([^\/?#:]+)/);
  return m ? m[1].toLowerCase() : null;
}

// Other link tags with resources: <link rel=stylesheet href>, <iframe src>, <form action>, <img src>.
export const linkTags = (text) => findTags(text, 'link').map((t) => ({ ...t, href: t.attrs.href ?? null, rels: relTokens(t.attrs.rel), integrity: t.attrs.integrity ?? null }));

// Inline <script> blocks (no src) across a whole file: [{ content, startLine, index, attrs }].
export function inlineScripts(text) {
  const out = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
  for (const m of text.matchAll(re)) {
    const { attrs } = parseAttrs(m[1]);
    if (typeof attrs.src === 'string') continue;
    const contentIndex = m.index + m[0].indexOf('>') + 1;
    out.push({ content: m[2], attrs, index: contentIndex, startLine: text.slice(0, contentIndex).split('\n').length });
  }
  return out;
}

// <meta http-equiv="X" content="Y"> -> [{ httpEquiv (lower), content }]
export const metaHttpEquiv = (text) => findTags(text, 'meta').filter((t) => typeof t.attrs['http-equiv'] === 'string')
  .map((t) => ({ ...t, httpEquiv: t.attrs['http-equiv'].toLowerCase(), content: t.attrs.content ?? '' }));

// Inline event handler attributes (onclick=...). Returns [{ tag, attr, value, index }]
export function inlineHandlers(text) {
  const out = [];
  for (const m of text.matchAll(/<([a-zA-Z][\w-]*)\b([^>]*)>/g)) {
    for (const a of parseAttrs(m[2]).list) if (/^on[a-z]+$/.test(a.name)) out.push({ tag: m[1].toLowerCase(), attr: a.name, value: a.value, index: m.index });
  }
  return out;
}

// SRI value check: tokens "sha256-..|sha384-..|sha512-.." -> true if at least one valid-looking hash.
export const hasValidSri = (integrity) => typeof integrity === 'string' && integrity.trim().split(/\s+/).some((t) => /^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(t));
