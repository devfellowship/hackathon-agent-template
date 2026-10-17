#!/usr/bin/env bash
# Roda o agente desta pasta numa task, do mesmo jeito que o TestMyAgent, N vezes, e mostra o placar por caso e etapa.
# Uso: OPENROUTER_API_KEY=... evals/run-local.sh <p1|p2|p3|biblioteca|pasta-da-task> [vezes]
#   p1 = dfl-day4-backlog-bpmn · p2 = dfl-day4-frontsec-scan · p3 = dfl-day4-reuniao-proposta (clonados do GitHub)
# Usa o AGENTS.md, o CLAUDE.md e o skills/ do jeito que estão no disco agora (sem precisar de commit).
# Modelo padrão: um modelo GRÁTIS do OpenRouter. Troque com MODEL=openrouter/<id>.
# Assinante do OpenCode Go: MODEL=go roda opencode-go/deepseek-v4.1-flash, o mesmo modelo da final (login: opencode auth login).
# A avaliação final usa deepseek-v4.1-flash (paga pela DFL).
# Precisa de: node 22+, npm e git. Usa o opencode instalado ou baixa com npx.
# Resumo em JSON (para o seu CLI ler): /tmp/dfl-eval/ultimo.json
set -euo pipefail
AGENT="$(cd "$(dirname "$0")/.." && pwd)"
ARG="${1:?uso: evals/run-local.sh <p1|p2|p3|biblioteca|pasta-da-task> [vezes]}"; N="${2:-1}"
MODEL="${MODEL:-openrouter/nvidia/nemotron-3-super-120b-a12b:free}"
[ "$MODEL" = go ] && MODEL=opencode-go/deepseek-v4.1-flash
TIMEOUT="${TIMEOUT:-600}"
OUTDIR="/tmp/dfl-eval"; mkdir -p "$OUTDIR"

case "$ARG" in
  p1|P1) SLUG=dfl-day4-backlog-bpmn ;;
  p2|P2) SLUG=dfl-day4-frontsec-scan ;;
  p3|P3) SLUG=dfl-day4-reuniao-proposta ;;
  biblioteca) SLUG=""; TASK="$AGENT/examples/biblioteca" ;;
  *) SLUG=""; TASK="$(cd "$ARG" && pwd)" ;;
esac
if [ -n "$SLUG" ]; then
  TASK="${XDG_CACHE_HOME:-$HOME/.cache}/dfl-day4/$SLUG"
  if [ -d "$TASK/.git" ]; then git -C "$TASK" pull -q --ff-only || true
  else git clone -q --depth 1 "https://github.com/devfellowship/$SLUG.git" "$TASK"; fi
fi
[ -f "$TASK/instruction.md" ] || { echo "task inválida: $TASK (falta instruction.md)"; exit 2; }

if command -v opencode >/dev/null 2>&1; then OPENCODE=(opencode); else OPENCODE=(npx -y opencode-ai@latest); fi
case "$MODEL" in
  openrouter/*) [ -n "${OPENROUTER_API_KEY:-}" ] || echo "aviso: OPENROUTER_API_KEY não está definida" ;;
  opencode-go/*) echo "usando o OpenCode Go (precisa de login: opencode auth login → OpenCode Go)" ;;
esac

pass=0; runs=()
for i in $(seq 1 "$N"); do
  WS="$(mktemp -d)"
  cp -r "$TASK/environment/." "$WS/"
  mkdir -p "$WS/tests" "$WS/.opencode"
  cp -r "$TASK/tests/public" "$WS/tests/public"
  [ -f "$AGENT/AGENTS.md" ] && cp "$AGENT/AGENTS.md" "$WS/"
  [ -f "$AGENT/CLAUDE.md" ] && cp "$AGENT/CLAUDE.md" "$WS/"
  [ -d "$AGENT/skills" ] && cp -r "$AGENT/skills" "$WS/.opencode/skills"
  (cd "$WS" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null \
    && git init -q && git add -A && git -c user.email=eval@local -c user.name=eval commit -qm base)
  TRACE="$OUTDIR/trace-$i.jsonl"; REPORT="$OUTDIR/vitest-$i.json"; rm -f "$REPORT"
  start=$(date +%s)
  (cd "$WS" && timeout "$TIMEOUT" "${OPENCODE[@]}" run --pure --format json -m "$MODEL" "$(cat "$TASK/instruction.md")" > "$TRACE" 2>&1) || true
  secs=$(( $(date +%s) - start ))
  fora="$(cd "$WS" && git status --porcelain | grep -v -E '^.. (out/|node_modules/)' || true)"
  (cd "$WS" && npx vitest run tests/public --reporter=json --outputFile="$REPORT" >/dev/null 2>&1) || true
  RUN_JSON="$(RUN="$i" SECS="$secs" WS="$WS" TRACE="$TRACE" REPORT="$REPORT" FORA="$fora" node -e '
    const fs = require("fs"); const e = process.env;
    let tests = [];
    try {
      const r = JSON.parse(fs.readFileSync(e.REPORT, "utf8"));
      for (const f of r.testResults) for (const a of f.assertionResults)
        tests.push({ name: a.title, ok: a.status === "passed", erro: a.status === "passed" ? undefined : (a.failureMessages || []).join("\n").slice(0, 600) });
    } catch { tests = [{ name: "vitest", ok: false, erro: "os testes não rodaram (out/ vazio ou JSON inválido?)" }]; }
    const fora = e.FORA ? e.FORA.split("\n") : [];
    const ok = tests.length > 0 && tests.every(t => t.ok) && fora.length === 0;
    console.log(JSON.stringify({ run: +e.RUN, ok, passou: tests.filter(t => t.ok).length, total: tests.length,
      segundos: +e.SECS, fora_de_out: fora, tests, trace: e.TRACE, workspace: e.WS }));
  ')"
  runs+=("$RUN_JSON")
  echo "$RUN_JSON" | node -e '
    const r = JSON.parse(require("fs").readFileSync(0, "utf8"));
    console.log(`run ${r.run}: ${r.ok ? "PASS" : "FAIL"} · ${r.passou}/${r.total} testes · ${r.segundos}s · trace: ${r.trace}`);
    for (const t of r.tests) console.log(`  ${t.ok ? "ok  " : "FAIL"} ${t.name}`);
    if (r.fora_de_out.length) console.log("  escreveu fora de out/ (na final isso zera):\n" + r.fora_de_out.map(l => "    " + l).join("\n"));
    console.log(`  workspace: ${r.workspace}`);
  '
  [ "$(echo "$RUN_JSON" | node -e 'console.log(JSON.parse(require("fs").readFileSync(0,"utf8")).ok)')" = true ] && pass=$((pass + 1))
done
printf '%s\n' "${runs[@]}" | TASK="$TASK" MODEL="$MODEL" node -e '
  const runs = require("fs").readFileSync(0, "utf8").trim().split("\n").map(l => JSON.parse(l));
  const s = { task: process.env.TASK, modelo: process.env.MODEL, passou: runs.filter(r => r.ok).length, vezes: runs.length, runs };
  require("fs").writeFileSync("/tmp/dfl-eval/ultimo.json", JSON.stringify(s, null, 2));
'
echo "resultado: $pass/$N · resumo: $OUTDIR/ultimo.json"
