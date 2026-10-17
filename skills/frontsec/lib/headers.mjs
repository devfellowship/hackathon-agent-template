// HTTP security headers: case-insensitive lookup, CSP, HSTS, framing, nosniff, referrer, permissions, CORS.

// Lower-case all header names. Input: { Name: value } or [[name, value], ...] or { name: [v1, v2] }.
// Duplicate names: values collected in order. ex: normHeaders({ 'Content-Type': 'x' })['content-type'] === ['x']
export function normHeaders(raw) {
  const entries = Array.isArray(raw) ? raw : Object.entries(raw || {});
  const out = {};
  for (const [k, v] of entries) {
    const key = String(k).toLowerCase();
    (out[key] ||= []).push(...(Array.isArray(v) ? v : [v]));
  }
  return out;
}

// First value of a header (case-insensitive) or undefined. ex: getHeader(h, 'strict-transport-security')
export const getHeader = (raw, name) => {
  const v = normHeaders(raw)[name.toLowerCase()];
  return v ? v[0] : undefined;
};
export const getHeaderAll = (raw, name) => normHeaders(raw)[name.toLowerCase()] || [];

// ---------- CSP ----------
// Parse a CSP value: split by ';', each directive "name v1 v2". Names lower-cased.
// Duplicate directive: FIRST wins (CSP spec) unless opts.lastWins. Values kept as written.
// Returns { directives: { name: [values] }, order: [names] }.
// ex: parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline'").directives['script-src']
export function parseCsp(value, opts = {}) {
  const directives = {};
  const order = [];
  for (const part of String(value ?? '').split(';')) {
    const toks = part.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    const name = toks[0].toLowerCase();
    if (name in directives && !opts.lastWins) continue;
    if (!(name in directives)) order.push(name);
    directives[name] = toks.slice(1);
  }
  return { directives, order };
}

// Effective directive with fallback chain. Returns { name, values } of the first present, or null.
// Default chain for scripts: ['script-src', 'default-src']. CSP3 elements: ['script-src-elem','script-src','default-src'].
// ex: effectiveDirective(csp, ['script-src', 'default-src'])
export function effectiveDirective(csp, chain) {
  for (const name of chain) if (name in csp.directives) return { name, values: csp.directives[name] };
  return null;
}

// Which "bad" tokens are present in values. Exact compare by default (opts.ci for case-insensitive).
// ex: unsafeTokens(["'self'", "'unsafe-inline'"]) -> ["'unsafe-inline'"]
// Note: '*' is only the bare star; 'https://*.cdn.x' is a wildcard host, NOT '*'.
export function unsafeTokens(values, bad = ["'unsafe-inline'", "'unsafe-eval'", '*'], opts = {}) {
  const norm = (s) => (opts.ci ? s.toLowerCase() : s);
  const set = new Set(bad.map(norm));
  return values.filter((v) => set.has(norm(v)));
}

// Extra CSP checks (use only what the spec asks):
export const hasNonceOrHash = (values) => values.some((v) => /^'(nonce-|sha256-|sha384-|sha512-)/i.test(v));
export const hasStrictDynamic = (values) => values.some((v) => v.toLowerCase() === "'strict-dynamic'");
export const hasWildcardHost = (values) => values.some((v) => /\*/.test(v) && v !== '*');
// Scheme-only sources like 'https:', 'http:', 'data:', 'blob:'
export const schemeSources = (values) => values.filter((v) => /^[a-z][a-z0-9+.-]*:$/i.test(v));

// ---------- HSTS ----------
// Parse Strict-Transport-Security. Returns { present, maxAge (number|null), includeSubDomains, preload, directives }.
// Directive names case-insensitive; max-age may be quoted. ex: parseHsts('max-age=31536000; includeSubDomains').maxAge
export function parseHsts(value) {
  if (value === undefined || value === null) return { present: false, maxAge: null, includeSubDomains: false, preload: false, directives: {} };
  const directives = {};
  for (const part of String(value).split(';')) {
    const p = part.trim();
    if (!p) continue;
    const i = p.indexOf('=');
    const k = (i === -1 ? p : p.slice(0, i)).trim().toLowerCase();
    const v = i === -1 ? true : p.slice(i + 1).trim().replace(/^"(.*)"$/, '$1');
    if (!(k in directives)) directives[k] = v;
  }
  const ma = directives['max-age'];
  const maxAge = typeof ma === 'string' && /^\d+$/.test(ma) ? Number(ma) : null;
  return { present: true, maxAge, includeSubDomains: 'includesubdomains' in directives, preload: 'preload' in directives, directives };
}

// ---------- framing / misc ----------
// Clickjacking protection: X-Frame-Options DENY|SAMEORIGIN, or CSP frame-ancestors present.
export function framingProtection(raw) {
  const xfo = getHeader(raw, 'x-frame-options');
  const xfoOk = typeof xfo === 'string' && ['deny', 'sameorigin'].includes(xfo.trim().toLowerCase());
  const csp = getHeader(raw, 'content-security-policy');
  const fa = csp ? parseCsp(csp).directives['frame-ancestors'] : undefined;
  return { xfo: xfo ?? null, xfoOk, frameAncestors: fa ?? null, protected: xfoOk || !!fa };
}

export const nosniffOk = (raw) => (getHeader(raw, 'x-content-type-options') || '').trim().toLowerCase() === 'nosniff';

export const REFERRER_POLICIES = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'];
// Referrer-Policy (browser rule): join ALL Referrer-Policy headers with ',', the LAST RECOGNIZED token wins;
// none recognized/absent -> opts.default ('strict-origin-when-cross-origin'). unsafe = 'unsafe-url' | 'no-referrer-when-downgrade'.
// ex: referrerPolicy([['Referrer-Policy','no-referrer, foo']]).policy === 'no-referrer'
export function referrerPolicy(raw, opts = {}) {
  const unsafe = opts.unsafe || ['unsafe-url', 'no-referrer-when-downgrade'];
  const vals = getHeaderAll(raw, 'referrer-policy');
  const toks = vals.join(',').split(',').map((s) => s.trim().toLowerCase()).filter((t) => REFERRER_POLICIES.includes(t));
  const policy = toks.length ? toks[toks.length - 1] : (opts.default ?? 'strict-origin-when-cross-origin');
  return { present: vals.length > 0, policy, unsafe: unsafe.includes(policy) };
}

// All CSP policies (each Content-Security-Policy header is one policy; Report-Only ignored). -> [parseCsp(...)]
export const cspPolicies = (raw, opts) => getHeaderAll(raw, 'content-security-policy').map((v) => parseCsp(v, opts));

// Permissions-Policy "camera=(), geolocation=(self)" -> { camera: [], geolocation: ['self'] }
export function parsePermissionsPolicy(value) {
  const out = {};
  for (const part of String(value ?? '').split(',')) {
    const m = part.trim().match(/^([a-z0-9-]+)\s*=\s*(\*|\(([^)]*)\)|\S+)$/i);
    if (!m) continue;
    out[m[1].toLowerCase()] = m[2] === '*' ? ['*'] : m[3] !== undefined ? m[3].trim().split(/\s+/).filter(Boolean) : [m[2]];
  }
  return out;
}

// CORS: wildcard ACAO, credentials with wildcard/null origin.
export function corsInfo(raw) {
  const acao = getHeader(raw, 'access-control-allow-origin');
  const acac = (getHeader(raw, 'access-control-allow-credentials') || '').trim().toLowerCase() === 'true';
  const v = acao === undefined ? null : String(acao).trim();
  return { allowOrigin: v, credentials: acac, wildcard: v === '*', nullOrigin: v === 'null', wildcardWithCredentials: v === '*' && acac };
}

// Cookie-less info leak headers: Server / X-Powered-By with a version number.
export const versionLeak = (raw, names = ['server', 'x-powered-by']) => names.filter((n) => /\d/.test(getHeader(raw, n) || ''));
