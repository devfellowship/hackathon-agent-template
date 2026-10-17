// Generic helpers: text order, multi-key sort, grouping, sums, grading scales.

// Plain text order by UTF-16 code unit ("A" < "Z" < "_" < "a"). Never localeCompare.
export const txt = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// Compare arrays element by element with txt (or a custom cmp); shorter prefix first.
export const cmpArrays = (a, b, cmp = txt) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const c = cmp(a[i], b[i]);
    if (c) return c;
  }
  return a.length - b.length;
};

// Shortest array first, then element-wise text order.
export const cmpShortestThenText = (a, b) => a.length - b.length || cmpArrays(a, b);

// Generic value compare: numbers numerically, booleans false<true, arrays element-wise, else txt.
export const cmpAuto = (a, b) => {
  if (a === b) return 0;
  if (a === null || a === undefined) return b === null || b === undefined ? 0 : -1;
  if (b === null || b === undefined) return 1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  if (typeof a === 'boolean' && typeof b === 'boolean') return (a ? 1 : 0) - (b ? 1 : 0);
  if (Array.isArray(a) && Array.isArray(b)) return cmpArrays(a, b, cmpAuto);
  return txt(String(a), String(b));
};

// sortBy(arr, ...keys) returns a NEW stable-sorted array.
// key = 'field' (asc) | '-field' (desc) | fn(x) | { get: 'field'|fn, desc?: bool, cmp?: fn }
// ex: sortBy(items, '-prioridade', '-pontos', 'id')
// ex: sortBy(pkgs, 'name', { get: 'version', cmp: cmpVersion })
export function sortBy(arr, ...keys) {
  const specs = keys.map((k) => {
    if (typeof k === 'function') return { get: k, desc: false, cmp: cmpAuto };
    if (typeof k === 'string') {
      const desc = k.startsWith('-');
      const f = desc ? k.slice(1) : k;
      return { get: (x) => getPath(x, f), desc, cmp: cmpAuto };
    }
    const g = typeof k.get === 'string' ? (x) => getPath(x, k.get) : k.get;
    return { get: g, desc: !!k.desc, cmp: k.cmp || cmpAuto };
  });
  return arr
    .map((x, i) => ({ x, i }))
    .sort((p, q) => {
      for (const s of specs) {
        const c = s.cmp(s.get(p.x), s.get(q.x));
        if (c) return s.desc ? -c : c;
      }
      return p.i - q.i;
    })
    .map((p) => p.x);
}

const getPath = (obj, path) => path.split('.').reduce((o, k) => (o == null ? o : o[k]), obj);

// Unique by key, keeping the FIRST occurrence. ex: uniqBy(findings, (f) => `${f.rule}|${f.file}|${f.line}`)
export function uniqBy(arr, keyFn) {
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    const k = keyFn(x);
    if (!seen.has(k)) { seen.add(k); out.push(x); }
  }
  return out;
}

// Group into a Map preserving insertion order. ex: groupBy(findings, (f) => f.rule + ':' + f.file)
export function groupBy(arr, keyFn) {
  const m = new Map();
  for (const x of arr) {
    const k = keyFn(x);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(x);
  }
  return m;
}

// Sum of numbers, optionally mapped. ex: sum(items, (i) => i.pontos)
export const sum = (arr, fn = (x) => x) => arr.reduce((s, x) => s + fn(x), 0);

// Integer division rounding DOWN (floor), also for negatives. ex: floorDiv(25 * 10, 3) === 83
export const floorDiv = (a, b) => Math.floor(a / b);
export const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));
export const uniqSorted = (arr, cmp = txt) => [...new Set(arr)].sort(cmp);

// Grade from inclusive upper limits. scale = [[0,'A'],[15,'B'],[35,'C'],[59,'D'],[Infinity,'F']]
// ex: scaleGrade(16, scale) === 'C'. Use opts.forced (e.g. 'F') when a critical item forces the grade.
export function scaleGrade(value, scale, opts = {}) {
  if (opts.forced) return opts.forced;
  for (const [max, grade] of scale) if (value <= max) return grade;
  return scale[scale.length - 1][1];
}

// Highest-ranked label by an order list. ex: maxByOrder(['media','alta'], ['baixa','media','alta','critica']) === 'alta'
export function maxByOrder(values, order) {
  let best = null;
  for (const v of values) if (best === null || order.indexOf(v) > order.indexOf(best)) best = v;
  return best;
}

// Run ordered rules; return the label of the first rule whose test is true (or fallback).
// ex: firstMatch([[!item, 'inexistente'], [item.crit, 'critico']], 'aceita')
export function firstMatch(rules, fallback = null) {
  for (const [cond, label] of rules) if (typeof cond === 'function' ? cond() : cond) return label;
  return fallback;
}

// Safe wrapper: run fn, on error log it and return fallback (a broken stage must not kill the others).
export function safe(label, fn, fallback) {
  try {
    return fn();
  } catch (e) {
    console.error(`[${label}] ERROR: ${e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e}`);
    return fallback;
  }
}

// Count per key with ALL keys present (zeros included). ex: countKeys(achados, (a) => a.tipo, ['x','y']) -> { x: 2, y: 0 }
export function countKeys(arr, keyFn, keys) {
  const out = Object.fromEntries(keys.map((k) => [k, 0]));
  for (const x of arr) { const k = keyFn(x); out[k] = (out[k] || 0) + 1; }
  return out;
}
