// Text scanning: regex matches with index, exact-length tokens, call detection, argument inspection,
// sink segments, banners, source maps, storage keys, JWT and base64url.

// All matches of a regex (global flag added if missing). Each: { text, index, end, groups: [..captures] }
// ex: matchAll('a=1 b=2', /(\w)=(\d)/) -> [{ text:'a=1', index:0, end:3, groups:['a','1'] }, ...]
export function matchAll(line, re) {
  const g = re.flags.includes('g') ? re : new RegExp(re.source, re.flags + 'g');
  const out = [];
  for (const m of line.matchAll(g)) out.push({ text: m[0], index: m.index, end: m.index + m[0].length, groups: m.slice(1), named: m.groups || {} });
  return out;
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
export const escapeRegex = esc;

// Build a token regex: prefix + chars{min,max}.
// opts.boundary: 'none' (default; substring match, like a greedy scan), 'left', 'right', 'both'.
//   'right' = next char must NOT be in chars (so exactly-N tokens are not cut from longer runs).
//   'left'  = previous char must not be a word char [A-Za-z0-9_].
// ex: tokenRegex('key_', 'A-Za-z0-9', 24)            // key_ + 24 or more
// ex: tokenRegex('sec_', '0-9a-f', 32, 32, { boundary: 'right' })  // exactly 32 hex, not 33
export function tokenRegex(prefix, chars, min, max = null, opts = {}) {
  const b = opts.boundary || 'none';
  const q = max === null ? `{${min},}` : `{${min},${max}}`;
  const left = b === 'left' || b === 'both' ? '(?<![A-Za-z0-9_])' : '';
  const right = b === 'right' || b === 'both' ? `(?![${chars}])` : '';
  return new RegExp(`${left}${esc(prefix)}[${chars}]${q}${right}`, 'g');
}

// Common placeholder words. Use ONLY if the spec says placeholders are not secrets
// (a strict char class usually already rejects them, e.g. "SUA_CHAVE" has '_').
export function looksLikePlaceholder(s) {
  return /x{6,}|X{6,}|your|sua_|seu_|aqui|here|change|exemplo|example|placeholder|dummy|<|>|\.\.\.|\*{3,}/i.test(s);
}

// Find calls of a function name. Default: name must not be preceded by [A-Za-z0-9_$]
// ('.' before is allowed, so window.eval( counts; $eval( / retrieval( do not).
// opts.space: allow spaces between name and '(' (default false). opts.dotOnly: require '.' before.
// Returns [{ index, argStart }] where argStart is the index just after '('.
// ex: findCalls('x=eval(a)', 'eval') -> [{ index: 2, argStart: 7 }]
// ex: findCalls(line, 'new Function'); findCalls(line, 'setTimeout'); findCalls(line, 'insertAdjacentHTML', { dotOnly: true })
export function findCalls(line, name, opts = {}) {
  const pre = opts.dotOnly ? '(?<=\\.)' : '(?<![A-Za-z0-9_$])';
  const nm = esc(name).replace(/ /g, '\\s+');
  const re = new RegExp(`${pre}${nm}${opts.space ? '\\s*' : ''}\\(`, 'g');
  return matchAll(line, re).map((m) => ({ index: m.index, argStart: m.end }));
}

// Inspect the first argument starting at argStart (just after '(').
// Returns { first: first non-space char ('' if none), quote: '"'|"'"|'`'|null, isStringLiteral (only ' or "),
//           isTemplate, isEmpty (')' right away), literal: content of the quoted string or null, text: raw arg up to ',' or ')' at depth 0 }
// ex: firstArg('f( "a,b", c)', 2) -> { first:'"', isStringLiteral:true, literal:'a,b', ... }
export function firstArg(line, argStart) {
  let i = argStart;
  while (i < line.length && /\s/.test(line[i])) i++;
  const first = i < line.length ? line[i] : '';
  const quote = first === '"' || first === "'" || first === '`' ? first : null;
  let literal = null;
  if (quote) {
    let j = i + 1;
    let s = '';
    while (j < line.length && line[j] !== quote) {
      if (line[j] === '\\' && j + 1 < line.length) { s += line[j + 1]; j += 2; continue; }
      s += line[j++];
    }
    literal = j < line.length ? s : null;
  }
  // raw text of the first argument (depth-aware, quote-aware)
  let depth = 0;
  let q = null;
  let k = i;
  for (; k < line.length; k++) {
    const c = line[k];
    if (q) { if (c === '\\') k++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === '`') q = c;
    else if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { if (depth === 0) break; depth--; }
    else if (c === ',' && depth === 0) break;
  }
  return {
    first,
    quote,
    isStringLiteral: first === '"' || first === "'",
    isTemplate: first === '`',
    isEmpty: first === ')' || first === '',
    literal,
    text: line.slice(i, k).trim(),
  };
}

// Text after `from` up to (not including) the next stop char on the same line, or to the end.
// ex: segmentAfter('el.innerHTML = a + location.hash; x()', 14) -> ' a + location.hash'
export function segmentAfter(line, from, stop = ';') {
  const i = line.indexOf(stop, from);
  return line.slice(from, i === -1 ? line.length : i);
}

// Default HTML sinks (regexes). Assignment sinks reject '==' / '===' comparisons.
export const HTML_SINKS = {
  innerHTML: /\.innerHTML\s*\+?=(?!=)/g,
  outerHTML: /\.outerHTML\s*\+?=(?!=)/g,
  documentWrite: /document\.write\(/g,
  documentWriteln: /document\.writeln\(/g,
  insertAdjacentHTML: /\.insertAdjacentHTML\(/g,
  dangerouslySetInnerHTML: /dangerouslySetInnerHTML\s*[:=]/g,
  srcdoc: /\.srcdoc\s*\+?=(?!=)/g,
};

// Default user-controlled sources (literal text).
export const USER_SOURCES = ['location.hash', 'location.search', 'location.href', 'document.URL', 'document.referrer', 'window.name', 'event.data', 'document.cookie', 'document.documentURI', 'location.pathname'];

// Sink+source findings on one line. For each sink match, take segmentAfter(sink end, stop) and test
// if it contains (literally) any source. Returns [{ sink, index, segment, source }].
// opts.sinks = array of regexes (default: innerHTML, outerHTML, document.write(, insertAdjacentHTML( — pick from HTML_SINKS per spec)
// opts.sources = array of strings (per spec). opts.stop = ';' (segment end char)
// ex: findSinkWithSource('d.innerHTML = location.hash;', { sources: ['location.hash'] }) -> [{...}]
export function findSinkWithSource(line, opts = {}) {
  const sinks = opts.sinks || [HTML_SINKS.innerHTML, HTML_SINKS.outerHTML, HTML_SINKS.documentWrite, HTML_SINKS.insertAdjacentHTML];
  const sources = opts.sources || USER_SOURCES;
  const stop = opts.stop ?? ';';
  const out = [];
  for (const re of sinks) {
    for (const m of matchAll(line, re)) {
      const segment = segmentAfter(line, m.end, stop);
      const src = sources.find((s) => segment.includes(s));
      if (src) out.push({ sink: m.text, index: m.index, segment, source: src });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

// Dynamic code calls whose first argument is NOT a ' or " string literal (template ` counts as non-literal).
// opts.names default ['eval', 'new Function']; opts.literalQuotes default ['"', "'"]
// opts.alsoLiteralTemplateWithoutExpr: treat `abc` (no ${}) as literal (only if the spec says so).
// ex: findDynamicCode('window.eval(x)') -> [{ name:'eval', index:7 }]
export function findDynamicCode(line, opts = {}) {
  const names = opts.names || ['eval', 'new Function'];
  const lits = opts.literalQuotes || ['"', "'"];
  const out = [];
  for (const name of names) {
    for (const c of findCalls(line, name, opts.callOpts)) {
      const a = firstArg(line, c.argStart);
      let literal = lits.includes(a.first);
      if (opts.alsoLiteralTemplateWithoutExpr && a.isTemplate && a.literal !== null && !a.literal.includes('${')) literal = true;
      if (opts.emptyIsLiteral && a.isEmpty) literal = true;
      if (!literal) out.push({ name, index: c.index, arg: a });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

// setTimeout/setInterval called with a STRING first argument (code as string).
// ex: findStringTimers('setTimeout("go()", 10)') -> [{ name:'setTimeout', ... }]
export function findStringTimers(line, opts = {}) {
  const names = opts.names || ['setTimeout', 'setInterval'];
  const out = [];
  for (const name of names) for (const c of findCalls(line, name)) {
    const a = firstArg(line, c.argStart);
    if (a.isStringLiteral || (opts.templateCounts !== false && a.isTemplate)) out.push({ name, index: c.index, arg: a });
  }
  return out;
}

// storage.setItem calls with a quoted key. Returns [{ storage, key, index, keyIsLiteral }].
// opts.storages default ['localStorage']. Keys from variables come with key=null, keyIsLiteral=false.
// ex: findStorageSets("localStorage.setItem('auth_token', t)") -> [{ storage:'localStorage', key:'auth_token', ... }]
export function findStorageSets(line, opts = {}) {
  const storages = opts.storages || ['localStorage'];
  const method = opts.method || 'setItem';
  const out = [];
  for (const st of storages) {
    const re = new RegExp(`${esc(st)}\\s*\\.\\s*${esc(method)}\\s*\\(`, 'g');
    for (const m of matchAll(line, re)) {
      const a = firstArg(line, m.end);
      const ok = a.isStringLiteral && a.literal !== null;
      out.push({ storage: st, key: ok ? a.literal : null, keyIsLiteral: ok, index: m.index, arg: a });
    }
    if (opts.bracket !== false) {
      // localStorage['key'] = v  /  localStorage.key = v
      for (const m of matchAll(line, new RegExp(`${esc(st)}\\[\\s*(["'])(.*?)\\1\\s*\\]\\s*=(?!=)`, 'g'))) out.push({ storage: st, key: m.groups[1], keyIsLiteral: true, index: m.index, form: 'bracket' });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

// Case-insensitive "contains any of words". ex: containsAnyCI('SESSAO_ID', ['token','sessao']) === true
export const containsAnyCI = (s, words) => words.some((w) => s.toLowerCase().includes(w.toLowerCase()));

// Bundle banners like "/*! name@1.2.3 | MIT */" -> [{ name, version, id: 'name@1.2.3', index }]
// Scoped names (@scope/pkg) supported. opts.re to override.
export function findBanners(text, opts = {}) {
  const re = opts.re || /\/\*!\s*((?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)/gi;
  return matchAll(text, re).map((m) => ({ name: m.groups[0], version: m.groups[1], id: `${m.groups[0]}@${m.groups[1]}`, index: m.index }));
}

// Source map reference on a line: "//# sourceMappingURL=<target>" (also legacy "//@" and "/*# ... */").
// Returns { target, isDataUri, index } or null.
// ex: findSourceMapRef('x;//# sourceMappingURL=app.js.map') -> { target:'app.js.map', isDataUri:false }
export function findSourceMapRef(line, opts = {}) {
  const re = opts.allowLegacy === false ? /\/\/# sourceMappingURL=(\S+)/ : /(?:\/\/|\/\*)[#@]\s*sourceMappingURL=([^\s*]+)/;
  const m = line.match(re);
  if (!m) return null;
  return { target: m[1], isDataUri: m[1].startsWith('data:'), index: m.index };
}

// ---------- base64url / JWT ----------

// Decode base64url (no padding needed; '-' '_' accepted; also accepts '+' '/'). Returns a utf8 string.
export function b64urlDecode(s) {
  return Buffer.from(s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), 'base64url').toString('utf8');
}

// Decode a JWT string. Returns { header, payload, signature, raw } or null when it is not valid JSON.
// ex: decodeJwt(tok).payload.role
export function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    return { header: JSON.parse(b64urlDecode(parts[0])), payload: JSON.parse(b64urlDecode(parts[1])), signature: parts[2], raw: token };
  } catch {
    return null;
  }
}

// Find JWT-looking tokens (eyJ<header>.<payload>.<signature>) in a line and decode them.
// Returns [{ token, index, payload|null, header|null }]. opts.re to override.
// opts.requireDecodable: drop tokens whose payload is not JSON (default false: payload null).
export function findJwts(line, opts = {}) {
  const re = opts.re || /eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
  const out = [];
  for (const m of matchAll(line, re)) {
    const d = decodeJwt(m.text);
    if (!d && opts.requireDecodable) continue;
    out.push({ token: m.text, index: m.index, payload: d ? d.payload : null, header: d ? d.header : null });
  }
  return out;
}
