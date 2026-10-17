// Output checker. Run from the workspace root:
//   node .opencode/skills/frontsec/check.mjs [--cases casos] [--shape /tmp/shape.json] [--ints]
// Checks: out/<case>.json exists for every case folder, valid JSON, no stage is null (a crashed stage),
// optional shape (same keys and value types as an example JSON copied from the README), integers only,
// and NOTHING changed outside out/ (git status).
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i === -1 ? null : args[i + 1]; };
const casesDir = opt('--cases') || ['casos', 'cases', 'input', 'inputs'].find((d) => existsSync(d)) || 'casos';
const shapePath = opt('--shape');
const intsOnly = args.includes('--ints');
const errors = [];
const warnings = [];

const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);

// Compare value against an example. Example null = any type. Example [] = any array. Example array item[0] = item shape.
function shape(v, ex, path) {
  if (ex === null) return;
  const kv = kind(v);
  const ke = kind(ex);
  if (kv !== ke) {
    if (kv === 'null' && ke !== 'object' && ke !== 'array') warnings.push(`${path}: null where the example has ${ke} (ok only if README allows null)`);
    else errors.push(`${path}: type ${kv}, example has ${ke}`);
    return;
  }
  if (ke === 'object') {
    for (const k of Object.keys(ex)) if (!(k in v)) errors.push(`${path}.${k}: missing key`);
    for (const k of Object.keys(v)) if (!(k in ex)) errors.push(`${path}.${k}: key not in the README format`);
    for (const k of Object.keys(ex)) if (k in v) shape(v[k], ex[k], `${path}.${k}`);
  } else if (ke === 'array' && ex.length) {
    v.forEach((item, i) => shape(item, ex[0], `${path}[${i}]`));
  }
}

function walkNumbers(v, path) {
  if (typeof v === 'number' && !Number.isInteger(v)) errors.push(`${path}: ${v} is not an integer`);
  if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walkNumbers(x, `${path}.${k}`);
}

const cases = existsSync(casesDir) ? readdirSync(casesDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort() : [];
if (!cases.length) errors.push(`no case folders found in ${casesDir}/ (use --cases <dir>)`);
if (!existsSync('out')) errors.push('out/ does not exist');
let example = null;
if (shapePath) {
  try { example = JSON.parse(readFileSync(shapePath, 'utf8')); } catch (e) { errors.push(`bad --shape file: ${e.message}`); }
}
for (const c of cases) {
  const f = `out/${c}.json`;
  if (!existsSync(f)) { errors.push(`missing ${f}`); continue; }
  let data;
  try { data = JSON.parse(readFileSync(f, 'utf8')); } catch (e) { errors.push(`${f} invalid JSON: ${e.message}`); continue; }
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    for (const [k, v] of Object.entries(data)) if (v === null) errors.push(`${f}: "${k}" is null (did that stage crash? see solver stderr)`);
  }
  if (example) shape(data, example, c);
  if (intsOnly) walkNumbers(data, c);
}
try {
  const st = execSync('git status --porcelain --untracked-files=all', { encoding: 'utf8' });
  const outside = st.split('\n').filter(Boolean).filter((l) => !/^.. "?(out\/|node_modules)/.test(l));
  if (outside.length) errors.push(`changed OUTSIDE out/ (this zeroes the score; undo with git checkout/rm):\n  ${outside.join('\n  ')}`);
} catch {
  warnings.push('git status unavailable; make sure you only wrote in out/');
}
for (const w of warnings) console.log(`warn: ${w}`);
if (errors.length) { console.error(errors.map((e) => `ERROR: ${e}`).join('\n')); process.exit(1); }
console.log(`ok: ${cases.length} case(s) in ${casesDir}/ have valid out/<case>.json${example ? ' matching the shape' : ''}`);
