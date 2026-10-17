// Set-Cookie parsing with browser semantics (RFC 6265 + modern rules) and a cookie jar over steps.

// Parse one Set-Cookie header.
// Returns { name, value, attrs, list, raw, valid }
//   attrs: lower-case attribute name -> value (string) or true (flag). LAST occurrence wins (RFC 6265).
//   list: all attributes in order [{ name (lower), rawName, value }].
// ex: parseSetCookie('sid=1; Path=/; secure; SameSite=None').attrs -> { path:'/', secure:true, samesite:'None' }
export function parseSetCookie(header) {
  const parts = String(header).split(';');
  const nv = parts[0];
  const eq = nv.indexOf('=');
  const name = (eq === -1 ? '' : nv.slice(0, eq)).trim();
  const value = (eq === -1 ? nv : nv.slice(eq + 1)).trim();
  const attrs = {};
  const list = [];
  for (const p of parts.slice(1)) {
    const t = p.trim();
    if (!t) continue;
    const i = t.indexOf('=');
    const rawName = (i === -1 ? t : t.slice(0, i)).trim();
    const v = i === -1 ? true : t.slice(i + 1).trim();
    const n = rawName.toLowerCase();
    list.push({ name: n, rawName, value: v });
    attrs[n] = v;
  }
  return { name, value, attrs, list, raw: header, valid: eq !== -1 };
}

// Attribute present (flag or with value)? ex: hasAttr(c, 'secure')
export const hasAttr = (c, name) => name.toLowerCase() in c.attrs;
// String value of an attribute or null. ex: attrValue(c, 'samesite') -> 'Lax'
export const attrValue = (c, name) => (typeof c.attrs[name.toLowerCase()] === 'string' ? c.attrs[name.toLowerCase()] : null);

// RFC 6265 default-path of a request path: strip query; if empty or not starting '/', '/';
// if only one '/', '/'; else everything before the LAST '/'.
// ex: defaultPath('/api/login') === '/api'; defaultPath('/entrar') === '/'; defaultPath('/a/b/') === '/a/b'
export function defaultPath(requestPath) {
  const p = String(requestPath || '').split('?')[0].split('#')[0];
  if (!p.startsWith('/')) return '/';
  const i = p.lastIndexOf('/');
  return i <= 0 ? '/' : p.slice(0, i);
}

// Effective path: Path attribute if it starts with '/', else default-path of the request.
export function cookiePath(c, requestPath) {
  const p = attrValue(c, 'path');
  return p !== null && p.startsWith('/') ? p : defaultPath(requestPath);
}

// Effective domain: Domain attribute lower-cased without leading '.', else the request host (host-only).
// Returns { domain, hostOnly }.
export function cookieDomain(c, host) {
  const d = attrValue(c, 'domain');
  if (d !== null && d.replace(/^\./, '') !== '') return { domain: d.replace(/^\./, '').toLowerCase(), hostOnly: false };
  return { domain: String(host).toLowerCase(), hostOnly: true };
}

// RFC domain-match: host === domain or host ends with '.' + domain. A browser REJECTS a cookie whose Domain does not domain-match the host.
export const domainMatches = (host, domain) => { const h = host.toLowerCase(); const d = domain.toLowerCase(); return h === d || h.endsWith('.' + d); };

// Path-match (RFC 6265 5.1.4). ex: pathMatches('/api/x', '/api') === true; pathMatches('/apix', '/api') === false
export function pathMatches(reqPath, cookiePathValue) {
  if (reqPath === cookiePathValue) return true;
  if (!reqPath.startsWith(cookiePathValue)) return false;
  return cookiePathValue.endsWith('/') || reqPath[cookiePathValue.length] === '/';
}

// Parse an HTTP date (RFC 1123 "Wed, 21 Oct 2026 07:28:00 GMT", also RFC 850 / dashes). Returns ms or NaN.
export function parseHttpDate(s) {
  if (typeof s !== 'string') return NaN;
  let t = Date.parse(s);
  if (!Number.isNaN(t)) return t;
  t = Date.parse(s.replace(/-/g, ' '));
  return t;
}

// Lifetime in seconds relative to `nowIso`: Max-Age WINS over Expires; Expires -> (Expires - now)/1000.
// Returns { lifetime: number|null (null = session cookie), source: 'max-age'|'expires'|null, expiresAt: ms|null }.
// Invalid Max-Age (not /^-?\d+$/) is ignored (RFC); invalid Expires date is ignored.
// ex: lifetime(parseSetCookie('a=1; Max-Age=0'), '2026-01-01T00:00:00Z').lifetime === 0
export function lifetime(c, nowIso) {
  const now = Date.parse(nowIso);
  const ma = attrValue(c, 'max-age');
  if (ma !== null && /^-?\d+$/.test(ma)) {
    const n = Number(ma);
    return { lifetime: n, source: 'max-age', expiresAt: now + n * 1000 };
  }
  const ex = attrValue(c, 'expires');
  if (ex !== null) {
    const t = parseHttpDate(ex);
    if (!Number.isNaN(t)) return { lifetime: (t - now) / 1000, source: 'expires', expiresAt: t };
  }
  return { lifetime: null, source: null, expiresAt: null };
}

// SameSite value lower-cased ('strict'|'lax'|'none'), or opts.missing (default null) when absent/invalid.
// ex: sameSite(c) === 'none'; sameSite(c, { missing: 'lax' }) for the browser default.
export function sameSite(c, opts = {}) {
  const v = attrValue(c, 'samesite');
  const l = v === null ? null : v.toLowerCase();
  if (l === 'strict' || l === 'lax' || l === 'none') return l;
  if (l !== null && opts.invalid !== undefined) return opts.invalid;
  return opts.missing ?? null;
}

// Prefix rules. Returns null if ok/no prefix, else the reason.
// __Secure-: needs Secure. __Host-: needs Secure, NO Domain, Path attribute exactly '/'.
// opts.ci: case-insensitive prefix match (newer browsers). opts.requirePathAttr (default true): Path=/ must be written.
export function prefixViolation(c, opts = {}) {
  const n = opts.ci ? c.name.toLowerCase() : c.name;
  const sec = opts.ci ? '__secure-' : '__Secure-';
  const hst = opts.ci ? '__host-' : '__Host-';
  if (n.startsWith(sec) && !hasAttr(c, 'secure')) return 'secure-prefix-without-secure';
  if (n.startsWith(hst)) {
    if (!hasAttr(c, 'secure')) return 'host-prefix-without-secure';
    if (hasAttr(c, 'domain')) return 'host-prefix-with-domain';
    if (opts.requirePathAttr !== false ? attrValue(c, 'path') !== '/' : (attrValue(c, 'path') ?? '/') !== '/') return 'host-prefix-path-not-root';
  }
  return null;
}

// Name contains any word (case-insensitive). ex: nameContainsAny('__Host-SID', ['sid']) === true
export const nameContainsAny = (name, words) => words.some((w) => name.toLowerCase().includes(w.toLowerCase()));

// Fully interpret a Set-Cookie in the context of a response.
// ctx = { host, path (request path), time (ISO) }
// Returns parsed cookie + { domain, hostOnly, path, lifetime, lifetimeSource, expiresAt, isDeletion, identity, domainRejected }
//   isDeletion: lifetime !== null && lifetime <= 0 (Max-Age<=0 or Expires <= now).
//   identity: `${name}|${domain}|${path}`.
export function interpretSetCookie(header, ctx) {
  const c = parseSetCookie(header);
  const { domain, hostOnly } = cookieDomain(c, ctx.host);
  const path = cookiePath(c, ctx.path);
  const lt = lifetime(c, ctx.time);
  return {
    ...c,
    domain,
    hostOnly,
    path,
    lifetime: lt.lifetime,
    lifetimeSource: lt.source,
    expiresAt: lt.expiresAt,
    isDeletion: lt.lifetime !== null && lt.lifetime <= 0,
    identity: `${c.name}|${domain}|${path}`,
    domainRejected: !hostOnly && !domainMatches(ctx.host, domain),
  };
}

// Run a cookie jar over ordered steps.
// steps: [{ name?, path, time, setCookies: [header,...] }]  (map the spec's field names!), host: default host.
// Returns { identities: Map identity -> record, events: [...] } where record =
//   { name, domain, path, sets: [{ step, stepIndex, cookie }], deletions: [{ step, stepIndex, cookie }],
//     firstSetIndex, lastSetIndex, deletedAfterLastSet, alive (in jar at the end, ignoring time) }
// Deletions never create a record; a deletion of an unknown identity is listed in `orphanDeletions`.
// opts.rejectBadDomain: skip cookies whose Domain does not domain-match the host (browser rule; listed in `rejected`).
//   Default false = keep them (most specs do not mention it). Turn on only if the spec says so.
export function runJar(steps, host, opts = {}) {
  const identities = new Map();
  const events = [];
  const orphanDeletions = [];
  const rejected = [];
  steps.forEach((st, idx) => {
    for (const h of st.setCookies || []) {
      const c = interpretSetCookie(h, { host: st.host || host, path: st.path, time: st.time });
      if (c.domainRejected && opts.rejectBadDomain) { rejected.push({ stepIndex: idx, cookie: c }); continue; }
      events.push({ stepIndex: idx, step: st.name, cookie: c });
      if (c.isDeletion) {
        const r = identities.get(c.identity);
        if (r) { r.deletions.push({ step: st.name, stepIndex: idx, cookie: c }); r.alive = false; r.lastDeleteIndex = idx; }
        else orphanDeletions.push({ step: st.name, stepIndex: idx, cookie: c });
        continue;
      }
      if (!identities.has(c.identity)) identities.set(c.identity, { name: c.name, domain: c.domain, path: c.path, identity: c.identity, sets: [], deletions: [], firstSetIndex: idx, lastDeleteIndex: -1 });
      const r = identities.get(c.identity);
      r.sets.push({ step: st.name, stepIndex: idx, cookie: c });
      r.lastSetIndex = idx;
      r.alive = true;
    }
  });
  for (const r of identities.values()) r.deletedAfterLastSet = r.lastDeleteIndex > r.lastSetIndex;
  return { identities, events, orphanDeletions, rejected };
}

// Was identity deleted in step index `i`? ex: deletedInStep(rec, logoutIndex)
export const deletedInStep = (rec, i) => rec.deletions.some((d) => d.stepIndex === i);
// Was it set in any step strictly before index i?
export const setBefore = (rec, i) => rec.sets.some((s) => s.stepIndex < i);
