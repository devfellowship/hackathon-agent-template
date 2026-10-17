---
name: frontsec
description: Biblioteca Node testada + esqueleto de solver para tasks de auditoria de segurança frontend (varredura de build/headers, segredos, JWT, XSS, CSP/HSTS, source maps, dependências com semver e resolução do Node, cookies Set-Cookie, plano de correção com exceções, prioridade e nota). Use em toda task desse tipo.
---

# frontsec — como usar

Pasta: `.opencode/skills/frontsec/`. Arquivos:

- `lib/index.mjs` — importa tudo. No solver: `const L = await import(process.cwd() + '/.opencode/skills/frontsec/lib/index.mjs');`
- `templates/solve.template.mjs` — esqueleto do solver. Copie: `cp .opencode/skills/frontsec/templates/solve.template.mjs /tmp/solve.mjs`
- `check.mjs` — checador: `node .opencode/skills/frontsec/check.mjs --shape /tmp/shape.json --ints`

**O README da task manda.** Os padrões da biblioteca são só padrões: lista de fontes XSS, palavras sensíveis,
pontos, escala de nota, ordem de severidade, campos de entrada, nomes de saída — tudo vem do README.
Se o README diz diferente de um padrão, passe a opção ou escreva a regra à mão com os helpers.

## Receita

1. `cp .opencode/skills/frontsec/templates/solve.template.mjs /tmp/solve.mjs`
2. Preencha cada `TODO(spec)` com o valor do README (códigos de regra, pontos, nomes de campos, ordens).
   Apague etapas que a task não tem; crie etapas novas no mesmo estilo.
3. `node /tmp/solve.mjs exemplo-1` (um caso, imprime) e depois `node /tmp/solve.mjs` (todos).
4. `npx vitest run tests/public` → leia o diff (esperado × recebido), ache a regra do README, corrija, rode de novo.
5. Escreva `/tmp/shape.json` copiando o exemplo de saída do README e rode o `check.mjs`.

## Armadilhas que derrubam nota

- Ordem de texto = código de caractere (`L.txt`), nunca `localeCompare`. `'Z' < '_' < 'a'`, `assets/x` < `headers.json` < `index.html`.
- Versões: compare com `L.cmpVersion` (numérico), nunca como texto.
- "Arredondar para baixo" = `L.floorDiv`. Números da saída são inteiros.
- Linha começa em 1; arquivo minificado = linha 1. Mesmo (regra, arquivo, linha) conta uma vez (o `scanTree` já faz).
- Caminho relativo à pasta do build, com `/` (o `walk` já faz). Leia subpastas.
- Cookie: `Max-Age` vale mais que `Expires`; vida ≤ 0 = remoção; sem `Path` = caminho padrão da URL; `Domain` sem `.` inicial e minúsculo.
- Data "vencida": `L.isBefore(expira, auditoria)` (vencer no próprio dia ainda vale). Se o README disser outra coisa, use `L.isOnOrBefore`.
- Lista vazia sai `[]`, nunca `null`. Campo "ou null" sai `null` mesmo.

## Funções (assinatura → exemplo)

### util
- `txt(a,b)` ordem de texto simples → `arr.sort(L.txt)`
- `sortBy(arr, ...keys)` estável; `'campo'` asc, `'-campo'` desc, função, ou `{get, cmp, desc}` → `L.sortBy(itens, '-prioridade', '-pontos', 'id')`; versão: `L.sortBy(l, 'pacote', { get: 'versao', cmp: L.cmpVersion })`
- `cmpArrays(a,b)` / `cmpShortestThenText(a,b)` comparar listas de nomes (caminho mais curto, depois texto)
- `uniqBy(arr, keyFn)` / `groupBy(arr, keyFn)` (Map) / `uniqSorted(arr)`
- `sum(arr, fn)` → `L.sum(itens, (i) => i.pontos)`
- `floorDiv(a,b)` → `L.floorDiv(pontos * 10, esforco)`; `clamp(x, lo, hi)`
- `countKeys(arr, keyFn, chaves)` contagem com todas as chaves (zeros)
- `scaleGrade(v, scale, {forced})` limites inclusivos → `L.scaleGrade(16, [[0,'A'],[15,'B'],[35,'C'],[Infinity,'F']])` = `'C'`
- `maxByOrder(vals, ordem)` → `L.maxByOrder(['media','alta'], ['baixa','media','alta','critica'])` = `'alta'`
- `firstMatch([[cond, rótulo], ...], fallback)` regras em ordem (cond pode ser função) → motivo de exceção
- `safe(label, fn, fallback)` roda uma etapa sem derrubar as outras

### files
- `walk(root, {exts})` recursivo, caminhos POSIX relativos, ordenados → `L.walk(dist, { exts: ['.js','.html'] })`
- `extOf(file)`, `readText(p)`, `readJson(p)`, `readJsonOr(p, padrão)`
- `splitLines(text, {stripCR})` por `\n`; `eachLine(text, (linha, n) => ...)`; `lineOfIndex(text, idx)`
- `resolveFrom(arquivo, ref)` resolve `./`, `../`, `/` a partir da pasta do arquivo → `'assets/maps/a.js.map'` ou `null`
- `existsIn(root, rel)` arquivo existe dentro do root
- `listCases(dir)` pastas de casos; `writeOut('out/x.json', obj)` (recusa fora de `out/`)

### engine
- `scanTree(root, { rules, exts })` roda regras por linha em todos os arquivos (`exts: 'all'` = qualquer extensão).
  `rules = [{ code, exts, detect(linha, ctx) }]`; `detect` devolve `true/false` ou array de achados (objetos, ex.: `{ cred }`).
  `ctx = { file, lineNo, ext, root, lines }`. Retorna `{ findings: [{rule,file,line}] únicos e ordenados, hits: todos os brutos }`.
- `bannersByFile(root)` → Map arquivo → `[{ name, version, id: 'nome@versao' }]` (banners `/*! nome@1.2.3`, só `.js`)

### scan (texto)
- `matchAll(linha, re)` → `[{ text, index, end, groups }]`
- `tokenRegex(prefixo, chars, min, max?, {boundary})` → `L.tokenRegex('sk_live_', 'A-Za-z0-9', 24)` (24 ou mais); exato 32 hex sem cortar sequência maior: `L.tokenRegex('h_', '0-9a-f', 32, 32, { boundary: 'right' })`; "antes e depois não pode ser letra, dígito ou `_`": `{ boundary: 'word' }`. Padrão `boundary:'none'` = acha dentro de qualquer texto.
- `allSameChar(s)` placeholder de caracteres todos iguais; `findUrlCredentials(linha)` → `[{ user, pass, userinfo }]`; `findAtobLiterals(linha)` → `[{ decoded }]` (base64 padrão); `findPemBlocks(linhas)` → `[{ beginLine, body }]` (chave privada, corpo sem espaços juntado)
- `looksLikePlaceholder(s)` só se o README falar de placeholder
- `findJwts(linha)` → `[{ token, payload, header }]` (payload decodificado de base64url; `null` se não for JSON) → `L.findJwts(l).filter((j) => !PUBLICOS.includes(j.payload?.role))`
- `decodeJwt(tok)`, `b64urlDecode(s)`
- `findSinkWithSource(linha, { sinks, sources, stop })` sink de HTML cujo trecho (até o próximo `;`) contém uma fonte escrita literalmente. Sinks prontos em `L.HTML_SINKS` (`innerHTML`, `outerHTML`, `documentWrite`, `documentWriteln`, `insertAdjacentHTML`, `dangerouslySetInnerHTML`, `srcdoc`); `==`/`===` não é sink. Padrão de sinks: innerHTML, outerHTML, document.write(, insertAdjacentHTML(. → `L.findSinkWithSource(l, { sources: ['location.hash','event.data'] })`
- `findDynamicCode(linha, { names, literalQuotes })` `eval(`/`new Function(` com 1º argumento que NÃO começa com `"` ou `'` (crase conta como não-literal; `window.eval(` conta; `$eval(` não)
- `findStringTimers(linha)` `setTimeout/setInterval` com string
- `findCalls(linha, nome, {dotOnly, space})` + `firstArg(linha, argStart)` → `{ first, isStringLiteral, isTemplate, literal, text }` para regras novas de chamada
- `findStorageSets(linha, { storages, bracket })` → `[{ storage, key, keyIsLiteral }]` (`localStorage.setItem('k', v)`; `bracket:false` ignora `localStorage['k']=`) → `.filter((s) => s.keyIsLiteral && L.containsAnyCI(s.key, ['token']))`
- `containsAnyCI(s, palavras)` contém, sem diferenciar maiúsculas
- `findBanners(texto)` → `[{ name, version, id }]`
- `findSourceMapRef(linha, {allowLegacy})` → `{ target, isDataUri }` ou `null`. Mapa exposto: `r.isDataUri || L.existsIn(root, L.resolveFrom(ctx.file, r.target))`
- `segmentAfter(linha, de, ';')`, `escapeRegex(s)`
- Fluxo de dados (taint) linha a linha: `const t = L.taintTracker({ sources, sanitizers })`; `t.isTainted(texto)`; `t.assign(nome, expr)` (contamina ou limpa); `t.addSource('ev.data')`.
  `parseVarAssignment(linha)` → `{ keyword, name, expr }` (`[const|let|var] x = ...`, não `==`, não `+=`); `containsName(texto, nome)` nome inteiro (`a.nome` não conta).
  `sinkSegments(linha, [regex...])` → `[{ sink, segment }]` para qualquer sink; prontos: `L.HTML_SINKS`, `L.EXEC_SINKS`, `L.REDIRECT_SINKS` (`locationHref`, `windowLocation`, `locationAssign`, `locationReplace`, `windowOpen`).
  `findMessageListeners(linhas)` → `[{ line, param, endLine, checksOrigin }]` (`addEventListener("message", ...)` até linha que começa com `})`; checa origem = `p.origin ===`/`!==`). Avalie os sinks da linha ANTES de aplicar a atribuição da mesma linha, se o README mandar.

### html (funciona numa linha ou no arquivo todo)
- `findTags(texto, 'a')` → `[{ attrs, raw, index }]` (atributos em minúsculas, aspas duplas/simples/sem aspas)
- `unsafeBlankLinks(texto, { exactTarget, needs })` `<a target=_blank>` sem `noopener`/`noreferrer` no `rel`
- `scriptSrcs(texto)` → `[{ src, scheme ('http','https','protocol-relative','relative'), integrity }]` → `.filter((s) => s.src.startsWith('http://'))`
- `urlScheme(url)`, `urlHost(url)`, `relTokens(v)`, `linkTags(texto)`, `hasValidSri(integrity)`
- `inlineScripts(texto)` → `[{ content, startLine }]`; `metaHttpEquiv(texto)`; `inlineHandlers(texto)` (`onclick=`...)

### headers (nomes sem diferenciar maiúsculas)
- `getHeader(h, nome)` (1ª ocorrência) / `getHeaderAll(h, nome)` / `normHeaders(h)` — `h` pode ser objeto ou lista de pares `[nome, valor]`
- `cspPolicies(h)` → uma política por header CSP (Report-Only ignorado)
- `parseCsp(valor)` → `{ directives: { 'script-src': [...] } }` (nome minúsculo; diretiva repetida: vale a 1ª)
- `effectiveDirective(csp, ['script-src','default-src'])` → `{ name, values }` ou `null` (nenhuma existe)
- `unsafeTokens(values, ruins = ["'unsafe-inline'","'unsafe-eval'",'*'], {ci})` → tokens ruins presentes (exato; `https://*.x` NÃO é `*`)
- `hasNonceOrHash`, `hasStrictDynamic`, `hasWildcardHost`, `schemeSources`
- `parseHsts(valor)` → `{ present, maxAge (número|null), includeSubDomains, preload }`
- `framingProtection(h)` (X-Frame-Options/frame-ancestors), `nosniffOk(h)`, `referrerPolicy(h)` (junta todos os headers, vale o último token reconhecido, padrão `strict-origin-when-cross-origin`), `parsePermissionsPolicy(v)`, `corsInfo(h)`, `versionLeak(h)`

### semver
- `parseVersion(v)`, `cmpVersion(a,b)` numérico, prerelease < release → `L.cmpVersion('1.10.0','1.9.0') > 0`
- `satisfies(v, faixa, {npmPrerelease})` suporta `||`, espaço (E), `>= <= > < =`, versão sem operador (=), `^ ~ x * 1.2 - 2.0` → `L.satisfies('1.4.2', '>=1.0.0 <1.4.5')`
- `smallestSafe(publicadas, instalada, faixasRuins)` menor versão > instalada fora de TODAS as faixas, ou `null`
- `sortVersions`, `maxSatisfying`, `majorOf(v)`, `diffKind(de, para)` (`'major'|'minor'|'patch'`)

### lock / deps
- `normalizeLock(lock)` aceita lockfile v1/v2/v3 → `{ packages }`; `nameOf(chave)` (depois do último `node_modules/`); `parentKey(chave)`
- `resolveDep(pkgs, de, nome)` resolução do Node (sobe pastas até `node_modules/nome`) → chave ou `null`
- `resolveTree(lock, { rootFields, depFields })` BFS da raiz → Map chave → `{ name, version, path (nomes), keys, viaDevOnly }`; caminho = mais curto, empate por texto. Padrão raiz: `dependencies`+`devDependencies`+`optionalDependencies` (siga o README!)
- `installed(lock)` todos os pacotes instalados
- Grafo: `const g = L.buildGraph(lock, { rootFields, depFields })` (nós = chaves de instalação, raiz = `''`).
  **Escolha a relação que o README DEFINE — leia a definição ao pé da letra:**
  - "dependentes diretos / quem depende de X" (1 passo): `L.directDependents(g, chave)` → ex.: `c` é exigido por `a` e `z` → `['node_modules/a','node_modules/z']`
  - "todos que dependem de X, direta ou indiretamente" (ancestrais): `L.allDependents(g, chave)`
  - "dependências diretas de X": `L.directDependencies(g, chave)`; "todas (transitivas)": `L.allDependencies(g, chave)`
  - "caminho" (um só, mais curto): `resolveTree(...).get(chave).path`; "todos os caminhos": `L.allPathsTo(g, chave)`
  - A raiz aparece como `''` — tire-a (`.filter(Boolean)`) se o README não conta o projeto. Converta chave → nome com `L.nameOf`.
- `mapAdvisories(lista, { id, pkg, range, severity })` renomeia campos da base de avisos
- `declaredRange(g, chaveDoDependente, nome)` faixa que o dependente declarou (raiz = `''`)
- `auditDeps({ lock, advisories, versions, severityOrder, bundleIds, treeOpts })` → um item por `nome@versao` vulnerável, ordenado por nome e versão:
  `{ pkg, version, id, key, advisories, advisoryIds, severity, path, keys, fix, inBundle, viaDevOnly }`
  Opções: `perCopy: true` (um item por cópia instalada, `id` = chave), `skipDev: true` (ignora `"dev": true`), `fixOpts: { skipPrerelease: true }`.

### cookies
- `parseSetCookie(h)` → `{ name, value, attrs }` (atributos em minúsculas; repetido: vale o último)
- `hasAttr(c,'secure')`, `attrValue(c,'samesite')`, `sameSite(c, {missing})` → `'strict'|'lax'|'none'|missing`
- `defaultPath('/api/login')` = `'/api'`; `cookiePath(c, caminhoDaURL)`; `cookieDomain(c, host)` → `{ domain, hostOnly }`
- `lifetime(c, momentoISO)` → `{ lifetime (seg|null), source }` (Max-Age > Expires; null = cookie de sessão)
- `prefixViolation(c, {ci})` regras `__Secure-`/`__Host-` (Host: Secure, sem Domain, `Path=/` escrito) → motivo ou `null`
- `nameContainsAny(nome, palavras)`, `domainMatches(host, dom)`, `pathMatches(req, path)`, `parseHttpDate(s)`
- `interpretSetCookie(h, { host, path, time })` → cookie + `{ domain, path, lifetime, isDeletion, identity }`
- `runJar(passos, host)` com `passos = [{ name, path, time, setCookies }]` → `{ identities: Map → { name, domain, path, sets:[{stepIndex, cookie}], deletions, ... } }`.
  Remoção (vida ≤ 0) não cria cookie; só remove a MESMA identidade (nome+domínio+caminho).
  `setBefore(rec, i)` gravado antes do passo i; `deletedInStep(rec, i)` removido no passo i.

- Pote de cookies do navegador (simulação completa): `const jar = L.createJar({ publicSuffixes, checks: [['secure_on_http','motivo_do_readme'], ...] })`
  `jar.expire(momento)`; `jar.receive(url, momento, setCookies)` → `[{ action: 'set'|'replace'|'delete'|'noop-delete'|'rejected', reason, cookie }]` (substituir mantém a posição de criação);
  `jar.cookiesFor(url, { context: 'same-site'|'cross-site', navigation, method })` ordenado por caminho mais longo e criação mais antiga; `L.cookieHeader(lista)` → `"a=1; b=2"`; `jar.list()`.
  Checks prontos (ordem padrão): `secure_on_http`, `public_suffix`, `domain_mismatch`, `host_prefix`, `secure_prefix`, `samesite_none_insecure`. Mapeie o `contexto` do README para `'same-site'`/`'cross-site'`.
- `parseUrl(url)` → `{ scheme, host, path, query }`; `isoNoMs(ms)` → `'2026-10-21T13:00:00Z'`

### dates (UTC)
- `toMs`, `cmpDate`, `cmpDay`, `dayOf`, `daysBetween(a,b)`, `secondsBetween(a,b)`, `addDays(d,n)`, `isBefore(a,b)`, `isOnOrBefore(a,b)`

## Plano de correção (padrões comuns)

- "mesma causa = um item": junte com um `Map` por id (`add(id, pontos, esforco)` do esqueleto soma pontos).
- Credencial distinta: use `hits` do `scanTree` (cada hit tem o texto em `cred`); a mesma credencial em 2 arquivos = 1 item.
- Absorção por biblioteca: arquivo com banner de pacote vulnerável → some pontos no item da dependência (veja `bannersByFile`).
- Exceções: julgue na ordem do README com `firstMatch`; aceita sai da lista; ignoradas com motivo.
- Prioridade: `floorDiv(pontos * 10, esforco)` (ou a fórmula do README). Ordene com `sortBy`.
