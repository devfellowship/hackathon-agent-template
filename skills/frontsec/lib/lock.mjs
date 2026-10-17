// package-lock parsing (v1, v2, v3) and Node module resolution, shortest dependency paths.
import { cmpArrays } from './util.mjs';

// Package name of an install key: text after the LAST "node_modules/". ex: nameOf('node_modules/a/node_modules/@s/b') === '@s/b'
export function nameOf(key) {
  const i = key.lastIndexOf('node_modules/');
  return i === -1 ? key : key.slice(i + 'node_modules/'.length);
}

// Parent install folder of an install key ('' for top level). ex: parentKey('node_modules/a/node_modules/b') === 'node_modules/a'
export function parentKey(key) {
  const i = key.lastIndexOf('/node_modules/');
  return i === -1 ? '' : key.slice(0, i);
}

// Normalize any lockfile to { packages: { '': root, 'node_modules/x': { version, dependencies, dev, optional, ... } } }.
// v2/v3 use `packages` directly. v1 (`dependencies` tree with `requires`) is converted.
export function normalizeLock(lock) {
  if (lock.packages && Object.keys(lock.packages).length) {
    const pk = { ...lock.packages };
    if (!pk['']) pk[''] = { name: lock.name, version: lock.version, dependencies: {} };
    return { packages: pk, version: lock.lockfileVersion ?? 2 };
  }
  const packages = { '': { name: lock.name, version: lock.version, dependencies: {}, devDependencies: {} } };
  const rec = (deps, prefix) => {
    for (const [name, d] of Object.entries(deps || {})) {
      const key = `${prefix}node_modules/${name}`;
      packages[key] = { version: d.version, dependencies: { ...(d.requires || {}) }, dev: !!d.dev, optional: !!d.optional };
      if (prefix === '') {
        if (d.dev) packages[''].devDependencies[name] = d.version;
        else packages[''].dependencies[name] = d.version;
      }
      rec(d.dependencies, `${key}/`);
    }
  };
  rec(lock.dependencies, '');
  return { packages, version: lock.lockfileVersion ?? 1 };
}

// Accept a whole lockfile (any version) or an already-normalized packages map.
export const asPkgs = (x) => ('' in x && !x.lockfileVersion ? x : normalizeLock(x).packages);

// Node resolution: from install key `from` ('' = project root) look for dep `name`:
// from/node_modules/name, then cut the last "/node_modules/<x>" and retry, ..., finally node_modules/name.
// Returns the install key or null. ex: resolveDep(pkgs, 'node_modules/a/node_modules/b', 'c')
export function resolveDep(pkgs, from, name) {
  let p = from;
  for (;;) {
    const cand = p ? `${p}/node_modules/${name}` : `node_modules/${name}`;
    if (pkgs[cand]) return cand;
    if (!p) return null;
    p = parentKey(p);
  }
}

// Dependency names declared by a package entry. fields default ['dependencies','optionalDependencies'];
// for the root use ['dependencies','devDependencies','optionalDependencies'] (follow the spec!).
export function depNames(entry, fields = ['dependencies', 'optionalDependencies']) {
  const out = [];
  for (const f of fields) for (const n of Object.keys((entry && entry[f]) || {})) if (!out.includes(n)) out.push(n);
  return out;
}

// BFS from the root following Node resolution. For every reachable install key, the best path of NAMES
// (shortest; tie -> element-wise plain text order). Handles cycles.
// Returns Map key -> { key, name, version, path: [names], keys: [install keys], depth, viaDevOnly }.
// opts.rootFields / opts.depFields choose which dependency maps are followed.
// opts.cmpPath to change tie-break (default shortest then text).
export function resolveTree(lockOrPkgs, opts = {}) {
  const pkgs = asPkgs(lockOrPkgs);
  const rootFields = opts.rootFields || ['dependencies', 'devDependencies', 'optionalDependencies'];
  const depFields = opts.depFields || ['dependencies', 'optionalDependencies'];
  const cmpPath = opts.cmpPath || ((a, b) => a.length - b.length || cmpArrays(a, b));
  const root = pkgs[''] || {};
  const best = new Map();
  const unresolved = [];
  let frontier = new Map();
  for (const f of rootFields) {
    for (const dep of Object.keys(root[f] || {})) {
      const k = resolveDep(pkgs, '', dep);
      if (!k) { unresolved.push({ from: '', name: dep }); continue; }
      const cand = { path: [nameOf(k)], keys: [k] };
      const prev = frontier.get(k);
      if (!prev || cmpPath(cand.path, prev.path) < 0) frontier.set(k, cand);
    }
  }
  while (frontier.size) {
    for (const [k, c] of frontier) best.set(k, c);
    const next = new Map();
    for (const [k, c] of frontier) {
      for (const dep of depNames(pkgs[k], depFields)) {
        const t = resolveDep(pkgs, k, dep);
        if (!t) { unresolved.push({ from: k, name: dep }); continue; }
        if (best.has(t)) continue;
        const cand = { path: [...c.path, nameOf(t)], keys: [...c.keys, t] };
        const prev = next.get(t);
        if (!prev || cmpPath(cand.path, prev.path) < 0) next.set(t, cand);
      }
    }
    frontier = next;
  }
  // dev-only reachability: reachable from non-dev roots?
  const prodReach = new Set();
  const stack = [];
  for (const f of rootFields.filter((x) => x !== 'devDependencies')) for (const dep of Object.keys(root[f] || {})) {
    const k = resolveDep(pkgs, '', dep);
    if (k && !prodReach.has(k)) { prodReach.add(k); stack.push(k); }
  }
  while (stack.length) {
    const k = stack.pop();
    for (const dep of depNames(pkgs[k], depFields)) {
      const t = resolveDep(pkgs, k, dep);
      if (t && !prodReach.has(t)) { prodReach.add(t); stack.push(t); }
    }
  }
  const out = new Map();
  for (const [k, c] of best) {
    out.set(k, { key: k, name: nameOf(k), version: pkgs[k].version, path: c.path, keys: c.keys, depth: c.path.length, viaDevOnly: !prodReach.has(k), entry: pkgs[k] });
  }
  out.unresolved = unresolved;
  out.unreachable = Object.keys(pkgs).filter((k) => k && !best.has(k) && k.includes('node_modules/'));
  return out;
}

// All installed packages (every key except the root) as [{ key, name, version, entry }].
export function installed(lockOrPkgs) {
  const pkgs = asPkgs(lockOrPkgs);
  return Object.keys(pkgs).filter((k) => k && k.includes('node_modules/')).map((k) => ({ key: k, name: nameOf(k), version: pkgs[k].version, entry: pkgs[k] }));
}

// ---------- graph relations (pick the one the spec DEFINES: direct vs transitive) ----------
// Edges follow Node resolution. Node ids are install keys; the project root is ''.
// buildGraph(lock, opts) -> { pkgs, out: Map key -> [child keys], in: Map key -> [parent keys] }
// opts.skipDev: ignore copies with "dev": true (as if not installed). opts.rootFields default all three maps.
export function buildGraph(lockOrPkgs, opts = {}) {
  const all = asPkgs(lockOrPkgs);
  const pkgs = opts.skipDev ? Object.fromEntries(Object.entries(all).filter(([k, v]) => k === '' || !v.dev)) : all;
  const rootFields = opts.rootFields || ['dependencies', 'devDependencies', 'optionalDependencies'];
  const depFields = opts.depFields || ['dependencies', 'optionalDependencies'];
  const out = new Map();
  const inn = new Map();
  for (const k of Object.keys(pkgs)) { out.set(k, []); inn.set(k, []); }
  for (const k of Object.keys(pkgs)) {
    for (const dep of depNames(pkgs[k], k === '' ? rootFields : depFields)) {
      const t = resolveDep(pkgs, k, dep);
      if (!t) continue;
      if (!out.get(k).includes(t)) out.get(k).push(t);
      if (!inn.get(t).includes(k)) inn.get(t).push(k);
    }
  }
  return { pkgs, out, in: inn };
}

// DIRECT dependencies of a package (one hop): install keys it resolves to. ex: directDependencies(g, 'node_modules/a')
export const directDependencies = (g, key) => [...(g.out.get(key) || [])];
// DIRECT dependents (one hop): who requires this exact install. '' = the project root.
// ex: directDependents(g, 'node_modules/c').map(nameOf)  -> ['a', 'z'] (the root shows as '')
export const directDependents = (g, key) => [...(g.in.get(key) || [])];

function reach(map, key) {
  const seen = new Set();
  const stack = [...(map.get(key) || [])];
  while (stack.length) {
    const k = stack.pop();
    if (seen.has(k) || k === key) continue;
    seen.add(k);
    stack.push(...(map.get(k) || []));
  }
  return [...seen];
}
// TRANSITIVE dependencies (all descendants, any depth). ex: allDependencies(g, 'node_modules/a')
export const allDependencies = (g, key) => reach(g.out, key);
// TRANSITIVE dependents (all ancestors, any depth; includes '' when reachable from the root).
export const allDependents = (g, key) => reach(g.in, key);

// Every simple path (list of install keys) from the root to `key` (no cycles). limit caps the count.
// ex: allPathsTo(g, 'node_modules/c').map((p) => p.map(nameOf))  -> [['a','b','c'], ['z','c']]
export function allPathsTo(g, key, limit = 1000) {
  const res = [];
  const rec = (k, path) => {
    if (res.length >= limit) return;
    if (k === key) { res.push(path); return; }
    for (const t of g.out.get(k) || []) if (!path.includes(t)) rec(t, [...path, t]);
  };
  rec('', []);
  return res;
}

// Declared range that `fromKey` ('' = root) wrote for dependency `name` (looks in the given fields). null if none.
// ex: declaredRange(g, 'node_modules/a', 'b') -> '^1.0.0'
export function declaredRange(g, fromKey, name, fields = ['dependencies', 'optionalDependencies', 'devDependencies', 'peerDependencies']) {
  const e = g.pkgs[fromKey] || {};
  for (const f of fields) if (e[f] && name in e[f]) return e[f][name];
  return null;
}
