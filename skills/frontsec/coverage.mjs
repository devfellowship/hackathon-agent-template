// Rule coverage: every numbered README rule must be handled in the solver.
// Tag the code that implements rule N with a comment "// R<N>" (several numbers allowed: "// R12 R13").
// Usage: node .opencode/skills/frontsec/coverage.mjs [README.md] [/tmp/solve.mjs]
// Prints the numbered rules that have NO "R<N>" tag in the solver, with their first words, so none is forgotten.
import { readFileSync } from 'node:fs';

const readme = readFileSync(process.argv[2] || 'README.md', 'utf8');
const solver = readFileSync(process.argv[3] || '/tmp/solve.mjs', 'utf8');
const rules = [];
for (const line of readme.split('\n')) {
  const m = line.match(/^(\d+)\.\s+(.*)$/); // top-level numbered items only (not indented sub-lists)
  if (m) rules.push({ n: Number(m[1]), text: m[2].replace(/\s+/g, ' ').slice(0, 90) });
}
if (!rules.length) {
  console.log('no numbered rules found in README; check each paragraph/table of the README by hand instead');
  process.exit(0);
}
const tagged = new Set();
for (const m of solver.matchAll(/\/\/.*$/gm)) for (const t of m[0].matchAll(/\bR(\d+)\b/g)) tagged.add(Number(t[1]));
const missing = rules.filter((r) => !tagged.has(r.n));
if (!missing.length) {
  console.log(`ok: all ${rules.length} numbered rules are tagged in the solver`);
} else {
  console.log(`MISSING ${missing.length}/${rules.length} rules (implement them, or tag "// R<n>" where already handled; if a rule is only input/format text, tag it too):`);
  for (const r of missing) console.log(`  R${r.n}: ${r.text}`);
  process.exit(1);
}
