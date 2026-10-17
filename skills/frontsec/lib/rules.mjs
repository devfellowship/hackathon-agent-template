// Ready-made line rules for scanTree. Each factory returns { code, exts, detect } whose detect ALWAYS returns
// an array of hit objects (empty array = no finding). Prefer these over hand-written detects.
import { existsIn, resolveFrom } from './files.mjs';
import { scriptSrcs, unsafeBlankLinks } from './html.mjs';
import { containsAnyCI, findDynamicCode, findJwts, findSinkWithSource, findSourceMapRef, findStorageSets, findStringTimers, matchAll } from './scan.mjs';

const JS_HTML = ['.js', '.html'];

// Secret tokens: one hit per regex match, hit.cred = matched text. opts.reject(text) drops placeholders.
// ex: ruleSecret('R1', [L.tokenRegex('sk_live_', 'A-Za-z0-9', 24)])
export const ruleSecret = (code, regexes, opts = {}) => ({
  code, exts: opts.exts || JS_HTML,
  detect: (l) => regexes.flatMap((re) => matchAll(l, re)).filter((m) => !(opts.reject && opts.reject(m.text))).map((m) => ({ cred: m.text, index: m.index })),
});

// JWTs judged by their payload. isBad(payload|null) -> true = finding. hit.cred = token.
// ex: ruleJwt('R3', (p) => !['anon', 'user'].includes(p?.role))
export const ruleJwt = (code, isBad, opts = {}) => ({
  code, exts: opts.exts || JS_HTML,
  detect: (l) => findJwts(l, opts).filter((j) => isBad(j.payload, j)).map((j) => ({ cred: j.token, index: j.index })),
});

// HTML sink fed by a literal source in its segment. ex: ruleSink('R4', { sources: [...], sinks: [...] })
export const ruleSink = (code, opts = {}) => ({ code, exts: opts.exts || JS_HTML, detect: (l) => findSinkWithSource(l, opts) });

// eval / new Function with non-literal first argument. ex: ruleDynamicCode('R5') or ruleDynamicCode('R5', { names: ['eval'] })
export const ruleDynamicCode = (code, opts = {}) => ({ code, exts: opts.exts || JS_HTML, detect: (l) => findDynamicCode(l, opts) });

// setTimeout/setInterval with a string. ex: ruleStringTimer('R12')
export const ruleStringTimer = (code, opts = {}) => ({ code, exts: opts.exts || JS_HTML, detect: (l) => findStringTimers(l, opts) });

// <script src> whose src passes test(src). ex: ruleScriptSrc('R6', (src) => src.startsWith('http://'))
export const ruleScriptSrc = (code, test, opts = {}) => ({ code, exts: opts.exts || ['.html'], detect: (l) => scriptSrcs(l).filter((s) => test(s.src, s)) });

// storage.setItem with a literal key containing any word (case-insensitive). ex: ruleStorageKey('R7', ['token', 'jwt'])
export const ruleStorageKey = (code, words, opts = {}) => ({
  code, exts: opts.exts || JS_HTML,
  detect: (l) => findStorageSets(l, { bracket: false, ...opts }).filter((s) => s.keyIsLiteral && containsAnyCI(s.key, words)),
});

// <a target=_blank> without noopener/noreferrer. ex: ruleBlankLink('R8', { exactTarget: true })
export const ruleBlankLink = (code, opts = {}) => ({ code, exts: opts.exts || ['.html'], detect: (l) => unsafeBlankLinks(l, opts) });

// Exposed source map: //# sourceMappingURL=<t> with data: URI or a target that exists in root (resolved from the file's folder).
// ex: ruleSourceMap('R11', distRoot)
export const ruleSourceMap = (code, root, opts = {}) => ({
  code, exts: opts.exts || ['.js'],
  detect: (l, ctx) => {
    const r = findSourceMapRef(l, opts);
    if (!r) return [];
    const exposed = (opts.dataUriCounts !== false && r.isDataUri) || existsIn(root, resolveFrom(ctx.file, r.target));
    return exposed ? [{ target: r.target }] : [];
  },
});

// Generic: regex on the line -> one hit per match. ex: ruleRegex('R13', /debugger;/g)
export const ruleRegex = (code, re, opts = {}) => ({ code, exts: opts.exts || JS_HTML, detect: (l) => matchAll(l, re).map((m) => ({ text: m.text, index: m.index })) });
