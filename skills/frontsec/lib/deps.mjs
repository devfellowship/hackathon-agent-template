// Vulnerable dependency audit: match installed packages against an advisory list.
import { installed, resolveTree } from './lock.mjs';
import { cmpVersion, satisfies, smallestSafe } from './semver.mjs';
import { maxByOrder, txt } from './util.mjs';

// auditDeps({ lock, advisories, versions, severityOrder, bundleIds, treeOpts, rangeOpts })
//   lock: parsed lockfile (any version)
//   advisories: [{ id, pkg, range, severity, ... }]  <- MAP the spec's field names to these first!
//   versions: { pkg: ['1.0.0', ...] } published versions (for the fix), or {} if none
//   severityOrder: lowest -> highest, e.g. ['low','moderate','high','critical'] (from the spec)
//   bundleIds: Set of 'name@version' found in the bundle (findBanners) -> `inBundle`
// opts.perCopy: one entry per installed copy (install key) instead of per name@version. opts.skipDev: ignore "dev": true copies.
// Returns one entry per distinct name@version that matches >=1 advisory, sorted by name (text) then version (numeric):
//   { pkg, version, id: 'pkg@version', advisories: [matching advisory objects], advisoryIds (sorted text),
//     severity (highest), path (best names path among copies), keys (install keys of all copies),
//     fix (smallest published version > installed outside ALL advisories of that pkg, or null),
//     inBundle, viaDevOnly (all copies only reachable via devDependencies) }
export function auditDeps({ lock, advisories, versions = {}, severityOrder = [], bundleIds = new Set(), treeOpts = {}, rangeOpts = {}, fixOpts = {}, perCopy = false, skipDev = false }) {
  const tree = resolveTree(lock, treeOpts);
  const byId = new Map();
  const cmpPath = treeOpts.cmpPath || ((a, b) => a.length - b.length || cmpNames(a, b));
  // perCopy: one entry per install key (id = key) and also copies unreachable from the root are evaluated.
  const nodes = perCopy ? installed(lock).map((n) => tree.get(n.key) || { ...n, path: null, viaDevOnly: true }) : [...tree.values()];
  for (const node of nodes) {
    if (!node.version) continue;
    if (skipDev && node.entry && node.entry.dev) continue;
    const hits = advisories.filter((a) => a.pkg === node.name && satisfies(node.version, a.range, rangeOpts));
    if (!hits.length) continue;
    const id = perCopy ? node.key : `${node.name}@${node.version}`;
    const prev = byId.get(id);
    if (prev) {
      prev.keys.push(node.key);
      prev.viaDevOnly = prev.viaDevOnly && node.viaDevOnly;
      if (cmpPath(node.path, prev.path) < 0) prev.path = node.path;
      continue;
    }
    const all = advisories.filter((a) => a.pkg === node.name);
    byId.set(id, {
      pkg: node.name,
      version: node.version,
      id,
      key: node.key,
      advisories: hits,
      advisoryIds: hits.map((a) => a.id).sort(txt),
      severity: maxByOrder(hits.map((a) => a.severity), severityOrder),
      path: node.path,
      keys: [node.key],
      fix: smallestSafe(versions[node.name] || [], node.version, all.map((a) => a.range), { ...rangeOpts, ...fixOpts }),
      inBundle: bundleIds.has(id),
      viaDevOnly: node.viaDevOnly,
    });
  }
  return [...byId.values()].sort((a, b) => txt(a.pkg, b.pkg) || cmpVersion(a.version, b.version) || txt(a.key, b.key));
}

const cmpNames = (a, b) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) { const c = txt(a[i], b[i]); if (c) return c; }
  return a.length - b.length;
};

// Map advisories with any field names to { id, pkg, range, severity }.
// ex: mapAdvisories(db.vulns, { id: 'ghsa', pkg: 'name', range: 'vulnerable', severity: 'level' })
export const mapAdvisories = (list, f) => list.map((a) => ({ ...a, id: a[f.id], pkg: a[f.pkg], range: a[f.range], severity: a[f.severity] }));
