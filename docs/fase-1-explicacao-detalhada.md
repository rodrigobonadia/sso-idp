# Fase 1 — Fundação: explicação detalhada

Este documento explica, arquivo por arquivo e trecho por trecho, tudo o que foi construído na Fase 1 do SSO IdP: o domínio, a persistência, a composição da aplicação Spring Boot e a containerização. A ideia é que você consiga olhar qualquer classe do projeto e entender exatamente por que ela existe e por que foi escrita daquele jeito.

---

## 1. A ideia por trás da Clean Architecture aqui

O projeto é um **monólito modular Maven** com 4 módulos, e a regra mais importante do projeto inteiro é esta:

```
sso-domain  →  sso-application  →  sso-infrastructure  →  sso-api
```

A seta indica "quem pode depender de quem". `sso-domain` não depende de ninguém (nem do Spring, nem do JPA). `sso-application` só depende de `sso-domain`. `sso-infrastructure` depende de `sso-application` (pra implementar as portas que ela define) e aí sim usa Spring/JPA/Postgres. `sso-api` depende de tudo e é onde o Spring Boot realmente "liga os fios".

Por que isso importa na prática: se um dia você quiser trocar Postgres por outro banco, ou trocar JPA por JDBC puro, ou até tirar o Spring inteiro, o `sso-domain` e o `sso-application` não mudam uma linha. Toda a lógica de negócio (o que é um Tenant, o que é um User, quando um usuário pode logar, como funciona a política de senha) fica isolada de qualquer framework.

Cada módulo tem seu próprio `pom.xml` — o do `sso-domain`, por exemplo, não importa nada além do JDK e das bibliotecas de teste (JUnit, AssertJ). Isso não é só documentação: se alguém tentar acidentalmente importar `org.springframework.*` dentro de `sso-domain`, o build quebra na hora, porque a dependência simplesmente não existe no classpath daquele módulo.

---

## 2. `sso-domain` — o coração do negócio

Este módulo não sabe que existe um banco de dados, uma API REST ou um framework. Ele só sabe as regras do negócio.

### 2.1. `Tenant.java` — o agregado raiz do tenant

```java
public final class Tenant {
    private final TenantId id;
    private final TenantSlug slug;
    private String name;
    private TenantStatus status;
    private final Instant createdAt;

    private Tenant(TenantId id, TenantSlug slug, String name, TenantStatus status, Instant createdAt) { ... }
```

O construtor é **privado**. Isso é proposital: a única forma de criar um `Tenant` é através de um dos dois métodos de fábrica abaixo, nunca "na mão" com `new Tenant(...)` de qualquer lugar do código.

```java
public static Tenant create(String name, TenantSlug slug) {
    return new Tenant(TenantId.generate(), slug, validateName(name), TenantStatus.ACTIVE, Instant.now());
}
```

`create()` é usado quando um tenant **novo** está nascendo: gera um ID novo, valida o nome, e já nasce com status `ACTIVE` e `createdAt = agora`.

```java
public static Tenant reconstitute(TenantId id, TenantSlug slug, String name, TenantStatus status, Instant createdAt) {
    ...
    return new Tenant(id, slug, validateName(name), status, createdAt);
}
```

`reconstitute()` é usado quando o tenant **já existe** e está sendo recriado a partir do banco (é o que o `TenantEntityMapper`, lá na infraestrutura, chama depois de ler uma linha do Postgres). A diferença chave: aqui o ID, o status e a data de criação vêm de fora (do banco), não são gerados agora.

Ter dois métodos de fábrica em vez de um construtor público genérico evita um bug clássico: alguém criar um "tenant novo" acidentalmente com um ID ou status errado vindos de algum lugar.

```java
public void suspend() {
    if (status == TenantStatus.SUSPENDED) {
        throw new TenantStateException("Tenant '" + slug + "' is already suspended");
    }
    this.status = TenantStatus.SUSPENDED;
}
```

Cada transição de estado (`suspend()`, `activate()`) se auto-protege contra ser chamada duas vezes seguidas — não existe "suspender um tenant já suspenso" silenciosamente; lança uma exceção de domínio (`TenantStateException`). Essa é a essência de "invariante encapsulado": ninguém de fora consegue colocar um `Tenant` num estado inconsistente, porque a única forma de mexer no estado é por esses métodos, e eles se auto-verificam.

```java
@Override
public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof Tenant tenant)) return false;
    return id.equals(tenant.id);
}
```

Igualdade é baseada **só no ID** — isso é o padrão DDD pra uma "Entity" (em oposição a um "Value Object", que teria igualdade por valor de todos os campos). Dois objetos `Tenant` com o mesmo ID são o "mesmo tenant", mesmo que um tenha o nome desatualizado em memória.

### 2.2. `TenantSlug.java` — Value Object com validação

```java
private static final Pattern PATTERN = Pattern.compile("^[a-z][a-z0-9-]{1,62}$");
```

O slug é o identificador amigável de URL do tenant (ex: `acme` em `acme.ssoplatform.example`). A regex garante: começa com letra minúscula, só tem letras minúsculas/números/hífen, e o tamanho total fica entre 2 e 63 caracteres (limite clássico de subdomínio DNS).

```java
public static TenantSlug of(String rawValue) {
    ...
    String normalized = rawValue.trim().toLowerCase();
    ...
    if (!PATTERN.matcher(normalized).matches()) {
        throw new InvalidTenantSlugException(...);
    }
    return new TenantSlug(normalized);
}
```

Repare que a normalização (`trim().toLowerCase()`) acontece **antes** da validação — então `" ACME "` e `"acme"` acabam sendo o mesmo slug. Isso é decisão consciente: evita ter dois tenants "Acme" e "ACME " que na prática deveriam ser o mesmo.

O construtor privado + fábrica estática (`of`) é o mesmo padrão usado em todo Value Object do projeto (`Email`, `TenantId`, `UserId`, `HashedPassword`, `RawPassword`): a única forma de existir uma instância válida é passando pela validação.

### 2.3. `User.java` — o agregado do usuário

```java
public static final int MAX_FAILED_LOGIN_ATTEMPTS = 5;
```

Constante de negócio: depois de 5 tentativas de login erradas seguidas, a conta é bloqueada automaticamente.

```java
public void recordFailedLogin() {
    this.failedLoginAttempts++;
    if (failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS && status == UserStatus.ACTIVE) {
        this.status = UserStatus.LOCKED;
    }
}
```

Isso é chamado toda vez que uma tentativa de autenticação falha (isso vai ser conectado de verdade na Fase 2, quando existir o endpoint de login). O contador incrementa, e se bater o limite **e** o usuário ainda estiver `ACTIVE`, o status vira `LOCKED` sozinho — não precisa de nenhuma lógica externa decidindo isso.

```java
public void recordSuccessfulLogin() {
    if (status != UserStatus.ACTIVE) {
        throw new UserStateException("User '" + email + "' cannot authenticate in status " + status);
    }
    this.failedLoginAttempts = 0;
}
```

Um login bem-sucedido zera o contador — mas só é permitido chamar isso se o usuário já estiver `ACTIVE`. Isso é uma trava de segurança: mesmo que alguém erre e chame esse método pra um usuário `LOCKED` ou `PENDING_VERIFICATION`, o domínio recusa.

Os status possíveis (`UserStatus` enum): `PENDING_VERIFICATION` (acabou de se registrar, ainda não confirmou e-mail) → `ACTIVE` (pode logar) → `LOCKED` (bloqueado por tentativas falhas, reversível via `unlock()`) ou `DISABLED` (desativado administrativamente, também reversível via `enable()`).

```java
public boolean canAuthenticate() {
    return status == UserStatus.ACTIVE;
}
```

Esse método existe pra centralizar a regra "quando um usuário pode logar" num único lugar — quem for escrever o endpoint de login na Fase 2 vai chamar isso em vez de reimplementar a checagem de status espalhada pelo código.

### 2.4. `RawPassword.java` — a política de senha como Value Object

```java
private static final int MIN_LENGTH = 10;
private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
private static final Pattern DIGIT = Pattern.compile("\\d");
private static final Pattern SPECIAL_CHAR = Pattern.compile("[^A-Za-z0-9]");
```

Regra de senha forte: mínimo 10 caracteres, pelo menos 1 maiúscula, 1 minúscula, 1 dígito e 1 caractere especial. Cada regra violada lança um erro específico (`WeakPasswordException`) com uma mensagem clara sobre qual regra falhou — importante pra UX do formulário de registro na Fase 2.

```java
@Override
public String toString() {
    return "RawPassword[REDACTED]";
}
```

Isso é uma proteção de segurança: se em qualquer lugar do código alguém (por engano) logar um objeto `RawPassword` (ex: `log.info("password: {}", rawPassword)`), o que vai aparecer no log é `RawPassword[REDACTED]`, nunca a senha em texto puro. O mesmo padrão existe em `HashedPassword`.

Esse valor **nunca é persistido** — ele existe só entre o momento em que o usuário digita a senha e o momento em que o `PasswordHasher` (porta da camada de aplicação) transforma isso num `HashedPassword`.

---

## 3. `sso-application` — os casos de uso

Esta camada orquestra o domínio, mas ainda não sabe nada de Spring, JPA ou HTTP — só define **portas** (interfaces) que a infraestrutura vai implementar depois.

### 3.1. As portas de saída (`port/out/`)

```java
public interface TenantRepository {
    Tenant save(Tenant tenant);
    Optional<Tenant> findById(TenantId id);
    Optional<Tenant> findBySlug(TenantSlug slug);
    boolean existsBySlug(TenantSlug slug);
}
```

Repare: a interface fala a língua do domínio (`Tenant`, `TenantId`, `TenantSlug`), nunca `TenantJpaEntity` ou qualquer coisa do JPA. Isso é o Princípio da Inversão de Dependência (o "D" do SOLID) na prática: a camada de aplicação **define o contrato** que ela precisa, e é a infraestrutura (uma camada "de fora") que vai **implementar** esse contrato — a seta de dependência aponta pra dentro, não pra fora.

O mesmo padrão vale pra `UserRepository` e `PasswordHasher` (que só expõe `hash(RawPassword)` e `matches(RawPassword, HashedPassword)` — o algoritmo real, BCrypt, é decisão da infraestrutura).

### 3.2. `CreateTenantUseCase.java`

```java
public CreateTenantResult execute(CreateTenantCommand command) {
    TenantSlug slug = TenantSlug.of(command.slug());
    if (tenantRepository.existsBySlug(slug)) {
        throw new DuplicateTenantSlugException(slug.value());
    }
    Tenant tenant = Tenant.create(command.name(), slug);
    Tenant saved = tenantRepository.save(tenant);
    return new CreateTenantResult(saved.id().value(), saved.slug().value(), saved.name());
}
```

Por que a checagem de slug duplicado está aqui e não dentro de `Tenant.create()`? Porque "esse slug já existe" é uma invariante que depende de **toda a coleção de tenants** — o `Tenant` sozinho, olhando só pra si mesmo, não tem como saber se existe outro igual em algum lugar. Esse tipo de invariante "que atravessa vários agregados" é exatamente o trabalho do caso de uso, não da entidade.

`CreateTenantCommand` e `CreateTenantResult` são `record`s simples — DTOs de entrada e saída do caso de uso, que isolam a "forma" da chamada de fora (futuramente, um controller REST) da forma interna do domínio.

### 3.3. `CreateUserUseCase.java`

```java
TenantId tenantId = TenantId.of(command.tenantId());
Tenant tenant = tenantRepository.findById(tenantId).orElseThrow(() -> new TenantNotFoundException(command.tenantId()));
if (!tenant.isActive()) {
    throw new TenantNotActiveException(tenant.slug().value());
}
```

Antes de criar um usuário, o caso de uso confirma duas coisas: que o tenant existe, e que ele está ativo (não faz sentido registrar um usuário novo debaixo de um tenant suspenso).

```java
Email email = Email.of(command.email());
if (userRepository.existsByTenantIdAndEmail(tenantId, email)) {
    throw new DuplicateEmailException(email.value());
}
```

Unicidade de e-mail é **por tenant**, não global — o mesmo e-mail pode existir em dois tenants diferentes (são organizações isoladas). É por isso que a chave única no banco é o par `(tenant_id, email)`, não só `email` sozinho (você vai ver isso na migration do Flyway).

```java
RawPassword rawPassword = RawPassword.of(command.rawPassword());
HashedPassword hashedPassword = passwordHasher.hash(rawPassword);
User user = User.register(tenantId, email, hashedPassword);
```

A senha em texto puro só existe entre essas duas linhas — é validada (`RawPassword.of`), imediatamente transformada em hash (`passwordHasher.hash`), e o `User` só guarda o hash a partir daí. O caso de uso nunca sabe que o hash é BCrypt — isso é decisão só da implementação da porta.

---

## 4. `sso-infrastructure` — onde o mundo real entra

### 4.1. Por que existem entidades JPA separadas das entidades de domínio?

`TenantJpaEntity` e `UserJpaEntity` são classes **paralelas** a `Tenant` e `User`, cheias de anotações `@Entity`, `@Column`, `@Enumerated`. Por quê não anotar o `Tenant` do domínio diretamente com `@Entity`?

Porque isso "vazaria" JPA pra dentro do domínio — o `sso-domain` deixaria de ter zero dependências de framework, e passaria a ficar acoplado ao Hibernate (construtor sem argumento exigido pelo JPA, proxies, lazy loading, etc.) mesmo em lugares que nunca tocam banco de dados, como os testes de domínio.

```java
protected TenantJpaEntity() {
    // required by JPA
}
```

Esse construtor protegido e vazio só existe porque o Hibernate precisa dele internamente (pra criar proxies via reflection) — mas ele nunca é usado pelo resto do código, só o construtor completo é.

### 4.2. Os *mappers* (`TenantEntityMapper`, `UserEntityMapper`)

```java
public static TenantJpaEntity toEntity(Tenant tenant) {
    return new TenantJpaEntity(tenant.id().value(), tenant.slug().value(), tenant.name(), tenant.status(), tenant.createdAt());
}

public static Tenant toDomain(TenantJpaEntity entity) {
    return Tenant.reconstitute(TenantId.of(entity.getId()), TenantSlug.of(entity.getSlug()), entity.getName(), entity.getStatus(), entity.getCreatedAt());
}
```

São classes estáticas, sem estado, com um único trabalho: traduzir domínio ↔ persistência nos dois sentidos. `toDomain()` usa `reconstitute()` (não `create()`) exatamente pelo motivo explicado lá em cima — o tenant já existia, só está sendo "remontado" a partir de uma linha do banco.

### 4.3. Os *adapters* (`TenantRepositoryAdapter`, `UserRepositoryAdapter`)

```java
@Repository
public class TenantRepositoryAdapter implements TenantRepository {
    private final TenantJpaRepository jpaRepository;

    @Override
    public Tenant save(Tenant tenant) {
        TenantJpaEntity saved = jpaRepository.save(TenantEntityMapper.toEntity(tenant));
        return TenantEntityMapper.toDomain(saved);
    }
```

Este é o ponto de encontro: implementa a porta `TenantRepository` (definida em `sso-application`), delegando pro `TenantJpaRepository` (interface do Spring Data JPA, que já vem com `save`/`findById` de graça) e usando o mapper pra traduzir de/pra domínio. É a única classe do projeto que enxerga tanto `Tenant` (domínio) quanto `TenantJpaEntity` (persistência) ao mesmo tempo.

Repare no `@Repository` do Spring — essa é a única anotação de framework aqui, e ela só existe na infraestrutura, nunca na interface `TenantRepository` que ela implementa.

### 4.4. `BCryptPasswordHasherAdapter.java`

```java
private static final int STRENGTH = 12;
private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(STRENGTH);
```

Implementa a porta `PasswordHasher` com BCrypt força 12 (o padrão do Spring Security é 10). Força mais alta = mais tempo de CPU por hash, o que é bom (dificulta ataque de força bruta offline se o banco vazar), mas também mais lento por login — 12 é um meio-termo comum em produção.

### 4.5. As migrations do Flyway

`V1__create_tenants_table.sql`:
```sql
CREATE TABLE tenants (
    id          UUID PRIMARY KEY,
    slug        VARCHAR(63)  NOT NULL,
    ...
    CONSTRAINT uk_tenants_slug UNIQUE (slug)
);
```

`V2__create_users_table.sql`:
```sql
CREATE TABLE users (
    id                     UUID PRIMARY KEY,
    tenant_id              UUID         NOT NULL REFERENCES tenants (id),
    email                  VARCHAR(255) NOT NULL,
    ...
    CONSTRAINT uk_users_tenant_email UNIQUE (tenant_id, email)
);
```

O Flyway numera e aplica essas migrations em ordem (`V1`, `V2`, ...) — é a **única fonte de verdade** do schema. No `application.yml`, `hibernate.ddl-auto: validate` diz pro Hibernate: "não crie nem altere tabela nenhuma sozinho, só confira se o que já existe bate com as entidades" — evita o clássico problema de o Hibernate "inventar" uma coluna diferente do que você esperava em produção.

Repare também o comentário dentro da migration `V2` explicando por que Row Level Security (isolamento de tenant no nível do próprio Postgres) foi **propositalmente adiado** pra Fase 5: hoje o isolamento é garantido pela aplicação (todo `UserRepository.find*` já recebe `tenantId`), e ativar RLS antes de existir um contexto de tenant por requisição faria consultas silenciosamente devolverem zero linhas em vez de dar erro — pior do que não ter RLS ainda.

---

## 5. `sso-api` — onde o Spring Boot liga tudo

### 5.1. `SsoApplication.java`

```java
@SpringBootApplication(scanBasePackages = "com.ssoplatform.idp")
@EntityScan(basePackages = "com.ssoplatform.idp.infrastructure.persistence.entity")
@EnableJpaRepositories(basePackages = "com.ssoplatform.idp.infrastructure.persistence.repository")
public class SsoApplication {
```

Por padrão, o Spring Boot só escaneia o pacote da classe `@SpringBootApplication` **e seus subpacotes**. Como `sso-domain`, `sso-application` e `sso-infrastructure` são pacotes **irmãos** de `com.ssoplatform.idp.api` (não filhos dele), foi preciso declarar explicitamente onde procurar: `scanBasePackages` pros beans do Spring em geral, `@EntityScan` pras entidades JPA, `@EnableJpaRepositories` pras interfaces de repositório do Spring Data.

### 5.2. `UseCaseConfiguration.java` — a raiz de composição

```java
@Bean
public CreateTenantUseCase createTenantUseCase(TenantRepository tenantRepository) {
    return new CreateTenantUseCase(tenantRepository);
}
```

Aqui está o motivo de existir essa classe: `CreateTenantUseCase` é uma classe **pura** (sem `@Service`, sem nenhuma anotação Spring), porque `sso-application` não pode depender de Spring. Então alguém, em algum lugar, precisa instanciar essa classe manualmente e registrá-la como bean — e esse "alguém" é a `UseCaseConfiguration`, que vive na camada mais externa (`sso-api`), a única que conhece tanto os casos de uso quanto os adapters concretos do Spring que vão ser injetados neles.

### 5.3. `application.yml`

```yaml
jpa:
  hibernate:
    ddl-auto: validate
flyway:
  enabled: true
  locations: classpath:db/migration
```

Já comentado acima — Flyway manda no schema, Hibernate só confere.

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
```

Só expõe `/actuator/health` e `/actuator/info` publicamente — não expõe endpoints sensíveis do Actuator (como `/actuator/env` ou `/actuator/beans`) sem querer.

---

## 6. Docker e docker-compose

### 6.1. `Dockerfile` — build multi-stage

```dockerfile
FROM maven:3.9-eclipse-temurin-21 AS build
...
COPY pom.xml .
COPY sso-domain/pom.xml sso-domain/pom.xml
...
RUN mvn -q -B dependency:go-offline

COPY sso-domain/src sso-domain/src
...
RUN mvn -q -B -DskipTests package
```

Truque clássico de cache de camadas do Docker: os `pom.xml` são copiados **antes** do código-fonte, e `dependency:go-offline` baixa todas as dependências nessa camada. Enquanto você só mexe em código Java (não em dependências), o Docker reaproveita essa camada já baixada em vez de rebaixar tudo a cada build.

```dockerfile
FROM eclipse-temurin:21-jre-jammy
RUN useradd --system --create-home --shell /usr/sbin/nologin sso
USER sso
```

Segundo estágio: imagem final só com o **JRE** (não o JDK completo, nem o Maven) — bem menor. E roda como usuário não-root (`sso`), não como `root` — boa prática de segurança em containers.

### 6.2. `docker-compose.yml`

```yaml
app:
  depends_on:
    postgres:
      condition: service_healthy
```

O container da aplicação só sobe depois que o Postgres passar no `healthcheck` (`pg_isready`), não só depois que ele "iniciar" — evita a race condition clássica de a aplicação tentar conectar antes do Postgres estar pronto pra aceitar conexões.

---

## 7. O `pom.xml` raiz e os dois bugs de ambiente que resolvemos

Vale registrar aqui porque foram decisões reais tomadas durante a Fase 1, não só "config padrão":

**Bug 1 — Testcontainers + Docker Desktop no Windows**: o Docker Desktop mais novo (Engine 29+) exige API mínima 1.40, mas o Testcontainers 1.20.x cai pra versão antiga 1.32 quando não negocia bem sobre TCP sem TLS (exatamente o cenário do Windows nativo sem WSL). Resolvido fixando a versão de API que o cliente pede:

```xml
<systemPropertyVariables>
    <api.version>1.44</api.version>
</systemPropertyVariables>
```

**Bug 2 — Failsafe + spring-boot-maven-plugin**: como o projeto não estende `spring-boot-starter-parent`, faltava uma configuração que ele dá de graça — sem ela, o Failsafe colocava o jar empacotado (fat jar) no classpath de teste em vez da pasta `target/classes` simples, quebrando a detecção de configuração do Spring nos testes. Resolvido com:

```xml
<classesDirectory>${project.build.outputDirectory}</classesDirectory>
```

Os dois ficam documentados com comentários no próprio `pom.xml` e na memória do projeto, justamente pra não serem esquecidos nem re-descobertos do zero numa próxima vez.

---

## 8. Os testes — o que cada suíte prova

| Suíte | Onde | O que prova |
|---|---|---|
| `TenantTest`, `TenantSlugTest`, `TenantIdTest` | `sso-domain` | Transições de estado, validação de slug/nome, igualdade por ID |
| `UserTest`, `EmailTest`, `RawPasswordTest`, `HashedPasswordTest`, `UserIdTest` | `sso-domain` | Política de senha, bloqueio automático, validação de e-mail, redação no `toString()` |
| `CreateTenantUseCaseTest`, `CreateUserUseCaseTest` | `sso-application` | Orquestração dos casos de uso com portas *mockadas* (Mockito) — cada exceção de negócio é testada isoladamente |
| `BCryptPasswordHasherAdapterTest` | `sso-infrastructure` | Hash/verificação de senha real, sem Spring |
| `TenantRepositoryAdapterIT`, `UserRepositoryAdapterIT` | `sso-infrastructure` | Persistência **real** contra um Postgres de verdade (Testcontainers) com as migrations do Flyway aplicadas — prova que o mapeamento JPA e as constraints do banco batem com o domínio |
| `SsoApplicationIT` | `sso-api` | Smoke test de ponta a ponta: sobe o contexto Spring completo, registra tenant + usuário através dos casos de uso reais, contra Postgres real |

A separação `*Test` (unitário, rodado pelo Surefire) vs `*IT` (integração, rodado pelo Failsafe) é deliberada: os unitários rodam em milissegundos sem precisar de Docker; os `*IT` sobem um Postgres de verdade e por isso são mais lentos, mas testam a integração de verdade, não um mock.

---

Isso cobre 100% do que existe hoje no repositório. Qualquer dúvida em algum arquivo específico, é só apontar que eu detalho ainda mais.
