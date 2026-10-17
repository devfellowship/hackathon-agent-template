# Como o seu CLI testa o agente da equipe

Isto é para o CLI que vocês usam para PROGRAMAR (Claude Code, Codex, Gemini CLI, Cursor, opencode).
O modelo do seu CLI (Cursor Auto, Opus, DeepSeek...) não importa: ele só edita os arquivos. Quem roda o agente é sempre
o opencode com o modelo escolhido em `MODEL`, igual à final.
Você, CLI, **não é o agente avaliado**. O agente avaliado é o `AGENTS.md` (ou `CLAUDE.md`) + `skills/` deste repo,
rodado pelo TestMyAgent com opencode e o modelo `deepseek-v4.1-flash`. Seu trabalho é melhorar esses arquivos
e medir com o mesmo runner. Não resolva os casos você mesmo.

## Rodar

```bash
evals/run-local.sh p1 3          # P1 backlog → BPMN (clona dfl-day4-backlog-bpmn)
evals/run-local.sh p2 3          # P2 segurança do frontend (dfl-day4-frontsec-scan)
evals/run-local.sh p3 3          # P3 reunião → proposta (dfl-day4-reuniao-proposta)
evals/run-local.sh biblioteca 1  # task de treino deste repo
```

- Duas formas de pagar o modelo:
  - **OpenCode Go** (assinatura): `MODEL=go evals/run-local.sh p1 3`. Roda `opencode-go/deepseek-v4.1-flash`, o mesmo
    modelo da final, então é o teste mais fiel. Precisa de login uma vez: `opencode auth login` → OpenCode Go.
  - **Chave da API da DeepSeek** (a mesma que se usa para ligar o Claude Code na DeepSeek):
    `export DEEPSEEK_API_KEY=...` e `MODEL=deepseek evals/run-local.sh p1 3`. Roda `deepseek/deepseek-flash`, que é o
    DeepSeek V4.1 Flash, o modelo da final.
  - **OpenRouter**: `OPENROUTER_API_KEY` no ambiente; o padrão é um modelo grátis (substituto do modelo da final).
  - Se nenhum dos dois estiver configurado, peça à pessoa. Nunca escreva a chave em arquivo.
- Usa os arquivos como estão no disco: não precisa de commit.
- Cada run leva até 10 min. Rode em segundo plano se o seu CLI tiver limite de tempo por comando.
- `MODEL=openrouter/<id>` ou `MODEL=opencode-go/<id>` troca o modelo. Modelo grátis tem limite (erro 429: espere e rode de novo).

## Ler o resultado

`/tmp/dfl-eval/ultimo.json`:

```json
{ "passou": 1, "vezes": 3, "runs": [ { "ok": false, "passou": 18, "total": 20,
  "tests": [ { "name": "exemplo-3 · cookies", "ok": false, "erro": "..." } ],
  "fora_de_out": [], "trace": "/tmp/dfl-eval/trace-1.jsonl", "workspace": "/tmp/tmp.XXXX" } ] }
```

- Cada teste é `<caso> · <etapa>`. Errar uma etapa não zera as outras.
- `fora_de_out` não vazio = o agente escreveu fora de `out/`. Na final isso zera a nota.
- `trace` mostra o que o agente fez, passo a passo. Leia antes de mudar o prompt.
- `workspace` guarda o `out/` que o agente gerou.

## Ciclo

1. Rode 3 vezes. 3/3 é estável, 1/3 é sorte.
2. Ache a etapa que mais falha e leia o trace dela.
3. Mude UMA coisa: `AGENTS.md`, uma skill ou um script em `skills/`.
4. Rode de novo e compare `passou`.

## Regras do que entra na final

- Só `AGENTS.md`, `CLAUDE.md` e `skills/` vão para o runner. Máximo 200 KB, sem symlink, só texto.
- Os 3 casos ocultos são diferentes dos exemplos: generalize, não decore respostas.
- Nunca edite nada em `examples/` nem no cache das tasks para "passar".
