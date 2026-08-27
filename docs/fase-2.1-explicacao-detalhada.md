# Fase 2.1 — Resolução de tenant por subdomínio: explicação detalhada

Este documento explica tudo o que foi implementado na Fase 2.1: como a aplicação descobre "de qual tenant é essa requisição" a partir do subdomínio, antes de qualquer controller rodar.

---

## 1. O problema que essa fase resolve

Você decidiu que cada tenant (empresa) vai ter seu próprio "endereço" — `acme.ssoplatform.example`, `globex.ssoplatform.example` etc. Antes de existir qualquer tela de login ou endpoint de negócio, a aplicação precisa de um mecanismo que, olhando pra requisição HTTP que chegou, descubra: "isso é a Acme? É a Globex? Ou não é tenant nenhum (é o domínio raiz, ou um endpoint de infraestrutura)?"

Esse mecanismo tem que rodar **antes** de qualquer controller, porque toda a Fase 2 em diante depende dele: a tela de login precisa saber de qual tenant mostrar o formulário, o registro precisa saber em qual tenant criar o usuário, e mais pra frente (Fase 3) o próprio fluxo OAuth vai depender de "que tenant é esse".

A peça central é um **filtro de Servlet** (`TenantResolutionFilter`), que intercepta toda requisição antes dela chegar em qualquer controller.

---

## 2. `sso-application` — o caso de uso que resolve o tenant

### `ResolveActiveTenantBySlugUseCase.java`

```java
public TenantSummary execute(String slugValue) {
    TenantSlug slug = TenantSlug.of(slugValue);
    Tenant tenant = tenantRepository.findBySlug(slug).orElseThrow(() -> new TenantNotFoundException(slugValue));
    if (!tenant.isActive()) {
        throw new TenantNotActiveException(tenant.slug().value());
    }
    return new TenantSummary(tenant.id().value(), tenant.slug().value(), tenant.name());
}
```

Repare que isso não é só "buscar o tenant pelo slug" — tem uma regra de negócio embutida: um tenant **suspenso** é tratado exatamente como um tenant que **não existe**, do ponto de vista de quem está tentando acessar por aquele subdomínio. Faz sentido: se a Acme for suspensa, ninguém deveria conseguir nem ver a tela de login dela.

Duas exceções diferentes são lançadas (`TenantNotFoundException` e `TenantNotActiveException`) mesmo que o resultado final pareça igual (bloquear o acesso) — isso é proposital: em outros pontos do sistema (como no cadastro de usuário) essas duas situações **precisam** ser diferenciadas (mensagens diferentes pro usuário), então elas continuam sendo tipos distintos. Quem decide "tratar os dois casos igual" é o filtro (camada de fora), não o caso de uso.

Esse caso de uso **reutiliza** as duas exceções que já existiam desde a Fase 1 (`TenantNotFoundException`, `TenantNotActiveException`) — só precisei adicionar um construtor novo em `TenantNotFoundException` que aceita um `slug` (String) além do que já aceitava um `tenantId` (UUID), porque aqui a busca é por slug, não por ID:

```java
public TenantNotFoundException(String slug) {
    super("No tenant found with slug '" + slug + "'");
}
```

Também ajustei a mensagem de `TenantNotActiveException`, que antes dizia especificamente "registration is not allowed" (só fazia sentido no contexto de cadastro de usuário) — generalizei pra "Tenant '...' is not active", já que agora essa exceção é usada em dois contextos diferentes.

### `TenantSummary.java`

```java
public record TenantSummary(UUID tenantId, String slug, String name) {}
```

É um DTO — a saída do caso de uso. Segue exatamente o mesmo princípio de `CreateTenantResult` (Fase 1): nunca devolver a entidade `Tenant` de domínio pra fora da camada de aplicação, só um "retrato" simples e imutável dela. Isso é o que o filtro (camada web) vai guardar como "o tenant desta requisição".

---

## 3. `sso-api` — a mecânica HTTP

### `TenantSlugExtractor.java` — a parte "pura" (sem Spring)

```java
public static Optional<String> extract(String host, String baseDomain) {
    ...
    if (normalizedHost.equals(normalizedBaseDomain)) {
        return Optional.empty();
    }
    String suffix = "." + normalizedBaseDomain;
    if (!normalizedHost.endsWith(suffix)) {
        return Optional.empty();
    }
    String prefix = normalizedHost.substring(0, normalizedHost.length() - suffix.length());
    if (prefix.isBlank() || prefix.contains(".")) {
        return Optional.empty();
    }
    return Optional.of(prefix);
}
```

Essa classe não sabe nada de HTTP, Servlet ou Spring — só recebe duas strings (`host`, `baseDomain`) e devolve um `Optional<String>` (o slug, se houver). Fiz questão de isolar essa lógica assim de propósito: ela é a parte mais "traiçoeira" de acertar (casos de borda de parsing de string), e isolada desse jeito dá pra testar com JUnit puro, sem precisar simular uma requisição HTTP inteira.

Passo a passo com `host = "acme.localhost"` e `baseDomain = "localhost"`:
1. `"acme.localhost".equals("localhost")` → falso, segue.
2. `suffix = ".localhost"`; `"acme.localhost".endsWith(".localhost")` → verdadeiro, segue.
3. `prefix = "acme.localhost".substring(0, tamanho - 10)` → `"acme"`.
4. `"acme"` não é vazio nem tem ponto → devolve `Optional.of("acme")`.

Com `host = "localhost"` (sem subdomínio): passo 1 já dá `equals` verdadeiro → devolve `Optional.empty()` — esse é o "escopo global", usado pra requisições que não pertencem a tenant nenhum.

Com `host = "a.b.localhost"` (subdomínio aninhado): o prefixo calculado seria `"a.b"`, que **contém ponto** → devolve vazio de propósito. Isso é porque um `TenantSlug` (Fase 1) só aceita um único rótulo (sem pontos) — em vez de deixar esse valor inválido chegar até `TenantSlug.of(...)` e estourar uma exceção de validação ali, a gente já filtra aqui e trata como "não é uma requisição de tenant válida".

7 testes cobrem isso: caso normal, case-insensitive, domínio raiz exato, domínio completamente não relacionado, subdomínio aninhado, domínio base com múltiplos rótulos (`ssoplatform.example` em vez de só `localhost`), e entradas nulas/vazias.

### `TenantContext.java` — o "quadro de avisos" da requisição

```java
@Component
@RequestScope
public class TenantContext {
    private TenantSummary tenant;
    public Optional<TenantSummary> tenant() { return Optional.ofNullable(tenant); }
    public void setTenant(TenantSummary tenant) { this.tenant = tenant; }
}
```

`@RequestScope` é a anotação do Spring que diz: "existe uma instância nova desse bean pra cada requisição HTTP, descartada quando ela termina". Isso é importante porque, sem isso, esse objeto seria um singleton compartilhado entre TODAS as requisições simultâneas — e aí a requisição da Acme veria o tenant resolvido da Globex se as duas chegassem ao mesmo tempo. Com `@RequestScope`, cada requisição tem sua própria "cópia limpa".

O filtro escreve nele (`setTenant`) logo no início da requisição; os controllers (que ainda vamos construir na Fase 2.2) vão **ler** dele (`tenant()`) pra saber pra qual tenant montar a tela ou processar o cadastro — sem precisar re-analisar o cabeçalho `Host` de novo em cada lugar.

### `TenantResolutionFilter.java` — o filtro em si

```java
@Component
@Order(TenantResolutionFilter.ORDER)
public class TenantResolutionFilter extends OncePerRequestFilter {

    public static final int ORDER = Integer.MIN_VALUE + 10;
```

`OncePerRequestFilter` é uma classe base do Spring que garante que o filtro roda **uma única vez** por requisição (importante porque, em certos cenários internos de forward/include do Servlet, um filtro "cru" pode rodar mais de uma vez sem essa garantia). `@Order` com um valor bem baixo (próximo do menor `int` possível) diz ao Spring "rode este filtro antes de praticamente tudo" — isso importa porque, na Fase 2.3, vamos adicionar o filtro de autenticação do Spring Security, que vai precisar que o tenant **já** esteja resolvido quando ele rodar.

```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
    if (isExempt(request)) {
        filterChain.doFilter(request, response);
        return;
    }

    Optional<String> slug = TenantSlugExtractor.extract(request.getServerName(), baseDomain);
    if (slug.isEmpty()) {
        filterChain.doFilter(request, response);
        return;
    }

    try {
        TenantSummary tenant = resolveActiveTenantBySlugUseCase.execute(slug.get());
        tenantContext.setTenant(tenant);
        filterChain.doFilter(request, response);
    } catch (TenantNotFoundException | TenantNotActiveException e) {
        response.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown or inactive tenant");
    }
}
```

Três caminhos possíveis, nessa ordem:

1. **Caminho isento** (`isExempt`, hoje só `/actuator/**`): passa direto, nem tenta resolver tenant. Isso é essencial pra manter o health check funcionando mesmo se alguém bater nele com um `Host` esquisito — monitoramento não pode depender de "existir um tenant".
2. **Sem subdomínio** (`slug.isEmpty()`): passa direto também, mas **sem** tenant resolvido — esse é o "escopo global" (domínio raiz).
3. **Com subdomínio**: chama o caso de uso. Se der certo, guarda o resultado no `TenantContext` e deixa a requisição seguir. Se der `TenantNotFoundException` ou `TenantNotActiveException`, a requisição é cortada ali mesmo com um 404 — **nenhum controller chega a rodar**.

Por que `response.sendError(...)` em vez de deixar a exceção subir pro tratamento de erro do Spring MVC? Porque um `Filter` roda **antes** do `DispatcherServlet` do Spring MVC — nesse ponto da cadeia, a infraestrutura de `@ExceptionHandler`/`@ControllerAdvice` ainda nem entrou em cena. Se eu deixasse a exceção escapar sem tratar, o container Servlet devolveria uma página de erro genérica e feia (ou um 500). Tratando aqui, no próprio filtro, eu controlo exatamente o código de status (404) e a mensagem.

### `application.yml` — de onde vem o domínio base

```yaml
app:
  tenant:
    base-domain: ${TENANT_BASE_DOMAIN:localhost}
```

O filtro recebe esse valor via `@Value("${app.tenant.base-domain}")` no construtor. Localmente, o padrão é `localhost` — e por isso `acme.localhost:8080` já funciona sem você configurar nada (todo navegador moderno resolve qualquer coisa `*.localhost` como `127.0.0.1` automaticamente). Em produção, você troca isso só ajustando a variável de ambiente `TENANT_BASE_DOMAIN` (já propagada no `docker-compose.yml` e documentada no `.env.example`) — nenhuma linha de código muda.

---

## 4. Os testes — o que cada um prova

`TenantSlugExtractorTest` (8 casos): a lógica pura de parsing, isolada, sem precisar de Spring nem de banco.

`ResolveActiveTenantBySlugUseCaseTest` (3 casos, Mockito): tenant ativo resolve certo; slug inexistente lança `TenantNotFoundException`; tenant suspenso lança `TenantNotActiveException` — tudo com o `TenantRepository` mockado, sem banco real.

`TenantResolutionFilterIT` (5 casos, Spring completo + Postgres real via Testcontainers) — este é o mais importante, porque prova o comportamento de ponta a ponta, com o filtro de verdade rodando dentro da cadeia real do Spring:

- Cria um tenant de verdade (`CreateTenantUseCase`, banco real), bate num endpoint de teste (`/ping`, que só existe dentro dessa suíte) usando `acme-filter-it.localhost` como host, e confirma que a requisição passa e devolve 200.
- Bate no mesmo endpoint com um host de tenant que nunca existiu → confirma 404.
- Cria um tenant, **suspende ele de verdade através do domínio** (`tenant.suspend()` + `tenantRepository.save(tenant)`, sem precisar de um caso de uso de suspensão que ainda não existe — isso fica pra Fase 6, console admin), e confirma que o subdomínio dele também dá 404 depois de suspenso.
- Bate no endpoint com host `"localhost"` puro (sem subdomínio) → confirma 200, sem tenant nenhum resolvido — o "escopo global" funcionando.
- Bate em `/actuator/health` com um host de tenant que não existe → confirma 200 mesmo assim, provando que a isenção do actuator funciona independente do host.

Um detalhe técnico desse teste: como simular "uma requisição chegou com o cabeçalho Host = acme.localhost" sem precisar de DNS de verdade? Uso o `MockMvc` do Spring (que não abre conexão de rede real) com um `RequestPostProcessor` que ajusta diretamente `request.setServerName(...)` antes da requisição ser processada — é a forma correta e confiável de testar isso, evitando a armadilha de tentar sobrescrever manualmente o cabeçalho `Host` via cliente HTTP real (a maioria das bibliotecas HTTP em Java, por segurança, proíbe sobrescrever esse cabeçalho especificamente).

---

Isso cobre 100% do que foi construído na Fase 2.1. Qualquer parte que você quiser que eu detalhe ainda mais, é só falar.
