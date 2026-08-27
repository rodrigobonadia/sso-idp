# SSO Platform

A custom-built, multi-tenant OAuth2/OIDC Identity Provider, implemented from scratch in Java/Spring Boot following Clean Architecture and SOLID principles.

This is not a wrapper around Spring Authorization Server, Keycloak, or any off-the-shelf IdP: the OAuth2/OIDC protocol itself (`/authorize`, `/token`, PKCE, JWKS, discovery, introspection, revocation, consent, etc.) is being implemented directly, on top of a hand-built domain model.

## Status

**Phase 1 of the roadmap** (see below): project foundation, Postgres persistence, and the core `Tenant`/`User` domain, with no HTTP endpoints yet.

## Architecture

The codebase is a Maven multi-module project that enforces Clean Architecture's Dependency Rule at compile time: inner modules cannot depend on outer ones.

| Module | Layer | May depend on | Notes |
|---|---|---|---|
| `sso-domain` | Entities | *(nothing but the JDK)* | Pure business rules: `Tenant`, `User`, value objects, domain exceptions. Zero framework dependencies. |
| `sso-application` | Use Cases | `sso-domain` | Orchestrates domain entities. Declares output ports (`TenantRepository`, `UserRepository`, `PasswordHasher`) as interfaces. Zero framework dependencies. |
| `sso-infrastructure` | Interface Adapters + Frameworks & Drivers | `sso-application`, `sso-domain` | Implements the output ports with Spring Data JPA / PostgreSQL / Flyway / BCrypt. |
| `sso-api` | Composition Root | all of the above | Spring Boot executable application. Wires use cases as beans (`UseCaseConfiguration`) and will host HTTP controllers from Phase 3 onward. |

Dependency Inversion in practice: `sso-application` defines `TenantRepository`/`UserRepository`/`PasswordHasher` as interfaces; `sso-infrastructure` implements them; `sso-api` wires the concrete implementation into the use case's constructor. Neither `sso-domain` nor `sso-application` imports Spring, JPA, or any other framework type.

## Multi-tenancy

Tenants are isolated by a `tenant_id` column (shared-schema strategy), enforced today at the application layer (every `UserRepository` query is scoped by tenant). Database-level Row Level Security policies are planned for Phase 5, once the web layer has a request-scoped tenant context to drive them.

## Running locally

Requirements: Docker and Docker Compose.

```bash
docker compose up --build
```

This builds the application image, starts PostgreSQL, waits for its health check, then starts the API on `http://localhost:8080` (override the port via `APP_PORT` in a `.env` file - see `.env.example`). Flyway applies all migrations automatically on startup.

## Running tests

```bash
mvn clean verify
```

Unit tests (`sso-domain`, `sso-application`) run with JUnit 5, AssertJ and Mockito and need no external services. Integration tests (`sso-infrastructure`, `sso-api`) use Testcontainers to spin up a real, ephemeral PostgreSQL instance - Docker must be running locally for those to execute.

## Roadmap

1. **Foundation** (current) - project structure, `Tenant`/`User` domain, Postgres + Flyway, Docker Compose.
2. Native authentication - login/registration pages, sessions, password recovery.
3. OAuth2/OIDC engine - `/authorize`, `/token`, PKCE, JWKS, discovery, consent screen.
4. Multi-factor authentication (TOTP, e-mail, SMS).
5. RBAC and multi-tenancy hardening (Row Level Security).
6. Admin web console.
7. Audit logging, rate limiting, observability.
8. Client SDKs.
9. CI/CD and final documentation.
