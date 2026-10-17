// SOLVER SKELETON. Copy to /tmp/solve.mjs, fill every "TODO(spec)" from README.md, delete stages the task does not have.
// Run from the workspace root:  node /tmp/solve.mjs            (all cases -> out/<case>.json)
//                               node /tmp/solve.mjs exemplo-1  (one case, also prints the JSON)
// RULE: README.md wins over every default of the library. Every number, list, name and sort order comes from the README.
// Tag the code of each numbered README rule N with a comment // RN, then: node .opencode/skills/frontsec/coverage.mjs README.md /tmp/solve.mjs
import { join } from 'node:path';
import { existsSync } from 'node:fs';
const L = await import(process.cwd() + '/.opencode/skills/frontsec/lib/index.mjs');

const CASES_DIR = 'casos'; // TODO(spec): folder with one subfolder per case
const ONLY = process.argv[2];

// ============ CONFIG — copy values from the README tables (never guess) ============
// Points per rule code, e.g. { R1: 40, R2: 3 }. Use the exact codes of the README.
const POINTS = {}; // TODO(spec)
const CRITICAL = new Set([]); // TODO(spec): codes that force the worst grade
// Grade scale: inclusive upper limits, e.g. [[0,'A'],[15,'B'],[35,'C'],[59,'D'],[Infinity,'F']]
const SCALE = []; // TODO(spec)
const WORST = 'F'; // TODO(spec): grade forced by a critical finding

// ============ STAGE: scan files (+ headers) ============
function stageScan(dir) {
  const root = join(dir, 'dist'); // TODO(spec): folder of the build
  // One entry per README rule that looks at file LINES. Use the ready factories (they always return arrays):
  //   L.ruleSecret(code, [regex...], { reject })   L.ruleJwt(code, (payload) => isFinding)   L.ruleSink(code, { sources, sinks })
  //   L.ruleDynamicCode(code, { names })           L.ruleScriptSrc(code, (src) => test)      L.ruleStorageKey(code, words)
  //   L.ruleBlankLink(code, { exactTarget })       L.ruleSourceMap(code, root)              L.ruleRegex(code, /re/g)   L.ruleStringTimer(code)
  // Hand-written rule: { code, exts, detect: (line, ctx) => ARRAY of hits } — return the finder's array (e.g. L.findJwts(l).filter(...)).
  // NEVER write `cond ? [{}] : []` or `arr ? ... : ...`: an empty array [] is TRUTHY in JS and fires on every line.
  // Delete every line below whose rule is not in the README; replace 'CODE_x' with the README codes. EXAMPLES:
  const rules = [
    // L.ruleSecret('CODE_secret', [L.tokenRegex('sk_live_', 'A-Za-z0-9', 24), L.tokenRegex('key_', '0-9a-f', 32, 32)]),
    // L.ruleJwt('CODE_jwt', (p) => !['anon'].includes(p?.role)),
    // L.ruleSink('CODE_xss', { sources: ['location.hash', 'location.search'] }),
    // L.ruleDynamicCode('CODE_eval'),
    // L.ruleScriptSrc('CODE_http_script', (src) => src.startsWith('http://')),
    // L.ruleStorageKey('CODE_storage', ['token']),
    // L.ruleBlankLink('CODE_blank', { exactTarget: true }),
    // L.ruleSourceMap('CODE_map', root),
  ];
  const { findings, hits } = L.scanTree(root, { rules, exts: ['.js', '.html'] }); // TODO(spec): which extensions are read ('all' = any)
  // A 'WARNING (likely BUG)' on stderr means a detect fires on almost every line: fix it before going on.

  // Header rules (one finding max each). EXAMPLE:
  const headers = L.readJsonOr(join(dir, 'headers.json'), {});
  const headerFindings = [];
  // const csp = L.getHeader(headers, 'content-security-policy');
  // const eff = csp === undefined ? null : L.effectiveDirective(L.parseCsp(csp), ['script-src', 'default-src']);
  // if (!eff || L.unsafeTokens(eff.values).length) headerFindings.push({ rule: 'R9', file: 'headers.json', line: 0 });
  // const hsts = L.parseHsts(L.getHeader(headers, 'strict-transport-security'));
  // if (hsts.maxAge === null || hsts.maxAge < 31536000) headerFindings.push({ rule: 'R10', file: 'headers.json', line: 0 });

  const all = L.sortBy([...findings, ...headerFindings], 'file', 'line', 'rule'); // TODO(spec): sort order
  const points = L.sum(all, (f) => POINTS[f.rule]);
  const grade = L.scaleGrade(points, SCALE, { forced: all.some((f) => CRITICAL.has(f.rule)) ? WORST : null });
  return {
    // TODO(spec): exact output field names
    out: { findings: all.map((f) => ({ rule: f.rule, file: f.file, line: f.line })), points, grade },
    all, hits, root,
  };
}

// ============ STAGE: dependencies ============
function stageDeps(dir, scan) {
  const lock = L.readJson(join(dir, 'lock.json')); // TODO(spec): file names
  const db = L.readJson(join(dir, 'advisories.json'));
  const advisories = L.mapAdvisories(db.advisories, { id: 'id', pkg: 'package', range: 'range', severity: 'severity' }); // TODO(spec): field names
  const bmap = L.bannersByFile(scan.root); // file -> [{ name, version, id }]
  const bundleIds = new Set([...bmap.values()].flat().map((b) => b.id));
  const list = L.auditDeps({
    lock, advisories,
    versions: db.versions || {}, // TODO(spec)
    severityOrder: ['low', 'medium', 'high', 'critical'], // TODO(spec): lowest -> highest
    bundleIds,
    // treeOpts: { rootFields: ['dependencies', 'devDependencies'] },  // TODO(spec): which root deps count
  });
  return {
    out: { vulnerable: list.map((d) => ({ package: d.pkg, version: d.version, advisories: d.advisoryIds, severity: d.severity, path: d.path, fix: d.fix, browser: d.inBundle })) }, // TODO(spec)
    list, bmap,
  };
}

// ============ STAGE: cookies / session ============
function stageSession(dir) {
  const s = L.readJson(join(dir, 'session.json')); // TODO(spec)
  const steps = s.steps.map((p) => ({ name: p.step, path: p.path, time: p.time, setCookies: p.set_cookie })); // TODO(spec): field names
  const logoutIdx = steps.findIndex((p) => p.name === 'logout'); // TODO(spec)
  const { identities } = L.runJar(steps, s.host);
  const SENSITIVE = []; // TODO(spec): words, e.g. ['sess', 'token']
  const ORDER = []; // TODO(spec): problem names IN README ORDER
  const cookies = [...identities.values()].map((r) => {
    const sens = L.nameContainsAny(r.name, SENSITIVE);
    const p = new Set();
    for (const { cookie: c } of r.sets) {
      // TODO(spec): one line per problem, e.g.
      // if (!L.hasAttr(c, 'secure')) p.add('no_secure');
      // if (sens && !L.hasAttr(c, 'httponly')) p.add('no_httponly');
      // if (sens && [null, 'none'].includes(L.sameSite(c))) p.add('weak_samesite');
      // if (L.prefixViolation(c)) p.add('bad_prefix');
      // if (sens && c.lifetime !== null && c.lifetime > 604800) p.add('long_expiry');
    }
    // if (sens && L.setBefore(r, logoutIdx) && !L.deletedInStep(r, logoutIdx)) p.add('not_cleared_on_logout');
    return { name: r.name, domain: r.domain, path: r.path, problems: ORDER.filter((x) => p.has(x)) };
  });
  return { out: { cookies: L.sortBy(cookies, 'name', 'domain', 'path') } }; // TODO(spec)
}

// ============ STAGE: plan (items, exceptions, priority) ============
function stagePlan(dir, scan, deps, sess) {
  const items = new Map(); // id -> { id, points, effort, critical }
  const add = (id, points, effort, critical = false) => {
    if (!items.has(id)) items.set(id, { id, points: 0, effort, critical });
    const it = items.get(id);
    it.points += points;
    it.critical ||= critical;
    return it;
  };
  // TODO(spec): build items exactly as the README table says. Typical patterns:
  // credential items, one per distinct credential text: for (const h of scan.hits) if (h.cred) { const id = 'cred:' + h.cred.slice(-8); if (!items.has(id)) add(id, POINTS[h.rule], 2, CRITICAL.has(h.rule)); }
  // per (rule, file): add(`code:${f.rule}:${f.file}`, POINTS[f.rule], EFFORT[f.rule])
  // per dependency: add(`dep:${d.id}`, d.inBundle ? pts : L.floorDiv(pts, 2), effort, d.severity === 'critical' && d.inBundle)
  // per cookie with problems: add(`cookie:${c.name}@${c.domain}${c.path}`, L.sum(c.problems, (x) => PP[x]), 1)
  // cross-stage attribution ("absorption"): a finding inside a file that carries the banner of a vulnerable package
  //   goes to that package's item instead of its own: const ids = (deps.bmap.get(f.file) || []).map((b) => b.id).filter((id) => depItems.has(id)).sort(L.txt);
  //   if (ids.length) { depItems.get(ids[0]).points += POINTS[f.rule]; continue; }   // build dep items BEFORE code items
  // Tag every block with the README rule number: // R38, // R39 ... and run coverage.mjs.

  const exc = L.readJsonOr(join(dir, 'exceptions.json'), { exceptions: [] }); // TODO(spec)
  const accepted = [];
  const ignored = [];
  for (const e of exc.exceptions) {
    const it = items.get(e.item);
    const reason = L.firstMatch([
      [!it, 'missing'], // TODO(spec): reasons and their ORDER
      [() => it.critical, 'critical'],
      [() => L.isBefore(e.expires, exc.audit_date), 'expired'],
    ], null);
    if (reason) ignored.push({ item: e.item, reason });
    else accepted.push(e.item);
  }
  const rest = [...items.values()].filter((it) => !accepted.includes(it.id))
    .map((it) => ({ ...it, priority: L.floorDiv(it.points * 10, it.effort) })); // TODO(spec): formula
  const sorted = L.sortBy(rest, '-priority', '-points', 'id'); // TODO(spec)
  const points = L.sum(sorted, (i) => i.points);
  return {
    items: sorted.map((i) => ({ id: i.id, points: i.points, effort: i.effort, priority: i.priority })),
    accepted: L.uniqSorted(accepted),
    ignored: L.sortBy(ignored, 'item'),
    points,
    effort: L.sum(sorted, (i) => i.effort),
    grade: L.scaleGrade(points, SCALE, { forced: sorted.some((i) => i.critical) ? WORST : null }),
  };
}

// ============ RUN ============
for (const c of L.listCases(CASES_DIR)) {
  if (ONLY && c !== ONLY) continue;
  const dir = join(CASES_DIR, c);
  const scan = L.safe(`${c} scan`, () => stageScan(dir), null);
  const deps = L.safe(`${c} deps`, () => stageDeps(dir, scan), null);
  const sess = L.safe(`${c} session`, () => stageSession(dir), null);
  const plan = L.safe(`${c} plan`, () => stagePlan(dir, scan, deps, sess), null);
  const out = {
    // TODO(spec): exact top-level keys
    scan: scan?.out ?? null,
    deps: deps?.out ?? null,
    session: sess?.out ?? null,
    plan: plan ?? null,
  };
  L.writeOut(`out/${c}.json`, out);
  if (ONLY) console.log(JSON.stringify(out, null, 2));
  else console.log(`ok out/${c}.json`);
}
