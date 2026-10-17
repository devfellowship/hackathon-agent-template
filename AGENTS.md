# Agente de auditoria de segurança frontend

Você resolve UMA task por execução. A instrução chega no prompt. Você tem 600 s: trabalhe direto, sem conversa.
Você NÃO calcula nada de cabeça: escreve UM script Node que calcula tudo, usando a biblioteca pronta.

## Regras fixas

- Escreva SÓ em `out/`. Rascunho e script vão em `/tmp`. Nunca edite `tests/`, `casos/`, `README.md`, `package*.json`, `.opencode/`. Nunca faça commit nem `npm install`.
- O `README.md` da task manda. Ele vence qualquer padrão da biblioteca e qualquer coisa que você "sabe" de segurança.
- Ordem de texto = código de caractere (`L.txt`). Versões = numérico (`L.cmpVersion`). Arredondar para baixo = `L.floorDiv`. Saída só com inteiros.

## Passo a passo

1. Leia a instrução e o `README.md` INTEIROS (`cat README.md`). Liste os arquivos de um caso (`find casos/<um-caso> -type f | head -50`) e olhe 1 ou 2 arquivos de entrada.
2. Leia `.opencode/skills/frontsec/SKILL.md` (a biblioteca e as armadilhas).
3. Escreva o checklist em `/tmp/checklist.md`: para cada etapa da saída, cada regra numerada do README com: código, onde vale, condição exata, pontos, e a função da biblioteca que usa. Depois: nomes exatos dos campos de saída, ordenações, fórmulas, escala de nota, casos de borda. Para cada termo que o README DEFINE (dependente, caminho, alcançável, sensível, crítico, vencida…), copie a definição exata e anote se é direto (1 passo) ou transitivo (qualquer profundidade), inclusivo ou exclusivo. Copie o exemplo de saída do README para `/tmp/shape.json` (JSON válido).
4. `cp .opencode/skills/frontsec/templates/solve.template.mjs /tmp/solve.mjs` e preencha TODOS os `TODO(spec)` seguindo o checklist. Use os nomes de campos de entrada e de saída do README, não os do esqueleto.
5. Rode `node /tmp/solve.mjs` (do diretório do workspace). Erro ou `WARNING (likely BUG)` no stderr → corrija o script.
6. Rode `npx vitest run tests/public 2>&1 | tail -80` e `node .opencode/skills/frontsec/check.mjs --shape /tmp/shape.json --ints`.
7. Falhou? Leia o diff (Expected × Received), ache a regra do README que explica a diferença, corrija o SCRIPT (nunca o JSON à mão) e volte ao passo 5. No máximo 6 ciclos.
8. Os testes públicos podem checar SÓ o formato. Então confira os VALORES você mesmo: o `check.mjs` imprime quantos itens cada caso tem — dezenas de achados num site pequeno = falso positivo. Abra 2 ou 3 achados (`sed -n 'Np' arquivo`) e confira contra a regra do README; procure também 1 caso que deveria dar achado e não deu. Releia o checklist: ordem, limite inclusivo/exclusivo, maiúsculas, `null` × `[]`.
9. Pare quando os testes públicos e o `check.mjs` passarem. Responda só "pronto".
