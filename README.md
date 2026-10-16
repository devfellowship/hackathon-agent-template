# Template de agente — Hackathon DFL Day 4 (UEM)

Este repositório é o ponto de partida do agente da sua equipe. O agente é avaliado no
[TestMyAgent](https://testmyagent.devfellowship.com) na rodada final, nos 4 casos (1 exemplo + 3 ocultos)
do problema que a sua equipe escolheu.

## 1. Crie o repo da equipe

1. Clique em **Use this template** → **Create a new repository**.
2. Deixe o repositório **público**. A produção clona o seu repo no commit entregue.

## 2. O que entra na avaliação

O runner do TestMyAgent copia **só** estes arquivos. O resto do repo não entra.

```text
AGENTS.md            obrigatório (ou CLAUDE.md): o prompt de sistema do agente
CLAUDE.md            opcional
skills/<nome>/SKILL.md   procedimentos; scripts auxiliares podem ficar junto (ex.: check.mjs)
```

- Tamanho máximo: 200 KB no total. Sem symlinks. Use só arquivos de texto em `skills/`.
- As skills ficam em `.opencode/skills/` dentro do workspace. O agente roda os scripts com `bash`.
- O modelo é fixo para todos: `deepseek-v4.1-flash`. O que muda é o harness.
- O agente roda sem internet (só a API do modelo), com limite de tempo da task (600 s) e de custo (US$ 0,50).
- O agente escreve **só** em `out/`. Um arquivo fora de `out/` zera a nota. Rascunho vai em `/tmp`.

`evals/` e `SUBMISSAO.md` são só para vocês. Eles não vão para o runner.

## 3. Teste local (o TestMyAgent roda só a final)

Precisa de Node 22+, git, [opencode](https://opencode.ai) e uma chave OpenRouter.
Modelos grátis para testar: artigo na wiki DFL (link no mural).

```bash
git clone <repo-modelo-das-tasks>          # tem a task de exemplo de cada problema
export OPENROUTER_API_KEY=...
evals/run-local.sh <repo-modelo-das-tasks>/p1-exemplo 3   # roda 3 vezes e conta os PASS
```

O script monta o workspace igual ao runner (environment + tests/public + seu AGENTS.md e skills/),
roda o opencode, roda os testes públicos e avisa se o agente escreveu fora de `out/`.

Dicas de harness:

- Rode 3 vezes: 3/3 é estável, 1/3 é sorte.
- Crie casos parecidos com o exemplo: os 3 casos ocultos não são o exemplo.
- Mude UMA coisa por vez (prompt, skill, script de checagem) e compare.
- Leia o trace (`/tmp/trace-N.jsonl`) para ver onde o agente se perde.

## 4. Entrega às 14:30

No slot da sua equipe no board do evento (seção SOLUÇÕES), preencha:

- Problema escolhido (P1, P2 ou P3)
- URL do repo público
- Commit SHA final (40 caracteres: `git rev-parse HEAD`)

Commit depois das 14:30 não conta. A produção roda a final no TestMyAgent; a DFL paga essa execução.
