// Semantic versions: parse, numeric compare (with prerelease), ranges (npm syntax), fix-version selection.

// Parse "1.2.3", "v1.2.3", "1.2.3-beta.1+build". Returns { major, minor, patch, pre: [ids], build, raw } or null.
export function parseVersion(v) {
  const m = String(v).trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/);
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ? m[4].split('.') : [], build: m[5] || '', raw: v };
}

const cmpPreId = (a, b) => {
  const an = /^\d+$/.test(a);
  const bn = /^\d+$/.test(b);
  if (an && bn) return +a - +b;
  if (an) return -1;
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
};

// Compare two versions NUMERICALLY part by part (1.10.0 > 1.9.0). Prerelease < release (1.0.0-rc.1 < 1.0.0).
// Build metadata ignored. ex: cmpVersion('1.0.10', '1.0.9') > 0
export function cmpVersion(a, b) {
  const x = typeof a === 'string' ? parseVersion(a) : a;
  const y = typeof b === 'string' ? parseVersion(b) : b;
  if (!x || !y) throw new Error(`bad version: ${!x ? a : b}`);
  for (const k of ['major', 'minor', 'patch']) if (x[k] !== y[k]) return x[k] - y[k];
  if (!x.pre.length && !y.pre.length) return 0;
  if (!x.pre.length) return 1;
  if (!y.pre.length) return -1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    if (x.pre[i] === undefined) return -1;
    if (y.pre[i] === undefined) return 1;
    const c = cmpPreId(x.pre[i], y.pre[i]);
    if (c) return c;
  }
  return 0;
}

export const sortVersions = (vs) => [...vs].sort(cmpVersion);
export const majorOf = (v) => parseVersion(v).major;
export const isPrerelease = (v) => parseVersion(v).pre.length > 0;

// ---------- ranges ----------
// Partial "1", "1.2", "1.x", "1.2.*", "*", "" -> { major, minor, patch, pre } with null for wildcards.
function parsePartial(s) {
  const t = s.trim().replace(/^v/, '');
  if (t === '' || t === '*' || t.toLowerCase() === 'x') return { major: null, minor: null, patch: null, pre: [] };
  const m = t.match(/^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/);
  if (!m) throw new Error(`bad version in range: "${s}"`);
  const n = (x) => (x === undefined || /^[xX*]$/.test(x) ? null : +x);
  const r = { major: n(m[1]), minor: n(m[2]), patch: n(m[3]), pre: m[4] ? m[4].split('.') : [] };
  if (r.major === null) { r.minor = null; r.patch = null; }
  if (r.minor === null) r.patch = null;
  return r;
}

const V = (ma, mi, pa, pre = []) => ({ major: ma, minor: mi, patch: pa, pre, build: '' });
const C = (op, v) => ({ op, v });
const ZERO_PRE = ['0'];

// Expand one comparator token into primitive comparators [{op, v}] (op in < <= > >= =).
function expand(op, s) {
  const p = parsePartial(s);
  const { major, minor, patch } = p;
  const full = major !== null && minor !== null && patch !== null;
  if (op === '^') {
    if (major === null) return [];
    if (major > 0 || minor === null) return [C('>=', V(major, minor ?? 0, patch ?? 0, p.pre)), C('<', V(major + 1, 0, 0, ZERO_PRE))];
    if (minor > 0 || patch === null) return [C('>=', V(0, minor, patch ?? 0, p.pre)), C('<', V(0, minor + 1, 0, ZERO_PRE))];
    return [C('>=', V(0, 0, patch, p.pre)), C('<', V(0, 0, patch + 1, ZERO_PRE))];
  }
  if (op === '~' || op === '~>') {
    if (major === null) return [];
    if (minor === null) return [C('>=', V(major, 0, 0)), C('<', V(major + 1, 0, 0, ZERO_PRE))];
    return [C('>=', V(major, minor, patch ?? 0, p.pre)), C('<', V(major, minor + 1, 0, ZERO_PRE))];
  }
  if (full) return [C(op || '=', V(major, minor, patch, p.pre))];
  // x-ranges with an operator
  if (major === null) return op === '<' || op === '>' ? [C('<', V(0, 0, 0, ZERO_PRE))] : [];
  const lo = V(major, minor ?? 0, 0);
  const hi = minor === null ? V(major + 1, 0, 0, ZERO_PRE) : V(major, minor + 1, 0, ZERO_PRE);
  switch (op || '=') {
    case '=': return [C('>=', lo), C('<', hi)];
    case '>=': return [C('>=', lo)];
    case '<': return [C('<', V(lo.major, lo.minor, 0, ZERO_PRE))];
    case '>': return [C('>=', minor === null ? V(major + 1, 0, 0) : V(major, minor + 1, 0))];
    case '<=': return [C('<', hi)];
    default: throw new Error(`bad operator ${op}`);
  }
}

// Parse a range into alternatives: [[{op, v}, ...], ...] (OR of ANDs).
// Supports: "||", spaces (AND), "a - b" hyphen, ^ ~ ~> >= <= > < =, x/X/* wildcards, partials, "" = any.
// Operators may be separated from the version by spaces (">= 1.2.0").
export function parseRange(range) {
  return String(range).split('||').map((alt) => {
    let s = alt.trim().replace(/(>=|<=|~>|>|<|=|\^|~)\s+/g, '$1');
    const hy = s.match(/^(\S+)\s+-\s+(\S+)$/);
    if (hy) {
      const lo = parsePartial(hy[1]);
      const hi = parsePartial(hy[2]);
      const out = [];
      if (lo.major !== null) out.push(C('>=', V(lo.major, lo.minor ?? 0, lo.patch ?? 0, lo.pre)));
      if (hi.major !== null) {
        if (hi.minor === null) out.push(C('<', V(hi.major + 1, 0, 0, ZERO_PRE)));
        else if (hi.patch === null) out.push(C('<', V(hi.major, hi.minor + 1, 0, ZERO_PRE)));
        else out.push(C('<=', V(hi.major, hi.minor, hi.patch, hi.pre)));
      }
      return out;
    }
    if (!s) return [];
    return s.split(/\s+/).flatMap((tok) => {
      const m = tok.match(/^(>=|<=|~>|>|<|=|\^|~)?(.*)$/);
      return expand(m[1] || '', m[2]);
    });
  });
}

const test = (c, v) => {
  const d = cmpVersion(v, c.v);
  switch (c.op) {
    case '>=': return d >= 0;
    case '<=': return d <= 0;
    case '>': return d > 0;
    case '<': return d < 0;
    default: return d === 0;
  }
};

// Is version inside range? Default: plain numeric comparison (prereleases compared like any version).
// opts.npmPrerelease: npm rule — a prerelease only matches if some comparator in the same alternative
// has a prerelease on the same major.minor.patch.
// ex: satisfies('2.3.1', '>=1.0.0 <2.3.4') === true; satisfies('4.1.3', '<4.1.3 || >=5.0.0 <5.0.4') === false
// ex: satisfies('1.9.9', '^1.2.0') === true; satisfies('0.3.0', '^0.2.1') === false; satisfies('1.2.9', '1.2.x') === true
export function satisfies(version, range, opts = {}) {
  const v = parseVersion(version);
  if (!v) throw new Error(`bad version: ${version}`);
  return parseRange(range).some((alt) => {
    if (!alt.every((c) => test(c, v))) return false;
    if (opts.npmPrerelease && v.pre.length) {
      return alt.some((c) => c.v.pre.length && c.v.pre !== ZERO_PRE && c.v.major === v.major && c.v.minor === v.minor && c.v.patch === v.patch);
    }
    return true;
  });
}

// Smallest version in `available` that is > installed and NOT inside any of `badRanges`. null if none.
// opts.allowEqual: also consider == installed. opts.skipPrerelease: ignore prerelease candidates.
// ex: smallestSafe(['2.3.1','2.3.2','2.3.4'], '2.3.1', ['>=1.0.0 <2.3.4']) === '2.3.4'
export function smallestSafe(available, installed, badRanges, opts = {}) {
  const cands = sortVersions(available.filter((v) => parseVersion(v)));
  for (const c of cands) {
    const d = cmpVersion(c, installed);
    if (d < 0 || (d === 0 && !opts.allowEqual)) continue;
    if (opts.skipPrerelease && isPrerelease(c)) continue;
    if (badRanges.some((r) => satisfies(c, r, opts))) continue;
    return c;
  }
  return null;
}

// Highest version of `available` matching range (npm "maxSatisfying"). null if none.
export function maxSatisfying(available, range, opts = {}) {
  const ok = available.filter((v) => parseVersion(v) && satisfies(v, range, opts));
  return ok.length ? sortVersions(ok).at(-1) : null;
}

// Kind of update between two versions: 'major' | 'minor' | 'patch' | 'prerelease' | 'none'.
export function diffKind(from, to) {
  const a = parseVersion(from);
  const b = parseVersion(to);
  if (a.major !== b.major) return 'major';
  if (a.minor !== b.minor) return 'minor';
  if (a.patch !== b.patch) return 'patch';
  return cmpVersion(a, b) ? 'prerelease' : 'none';
}
