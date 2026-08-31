-- Phase 3.1: manual test OAuth client, provisioned by hand via SQL (per the user's explicit
-- decision - see architecture_decisions.md, "clients are provisioned manually via hand-written
-- SQL/seed data for now"). This is NOT a Flyway migration: it is not auto-run on `docker compose
-- up`, so it will never insert test data into a real deployment. Run it yourself, once, against
-- your local Postgres, whenever you want a client row to test the OAuth2 endpoints against as
-- Phase 3 progresses (the /authorize and /token endpoints themselves are not built yet - this
-- only exercises the OAuthClientRepositoryAdapter/persistence layer added in this sub-phase).
--
-- How to run it (PowerShell, from the project root, with `docker compose up` already running):
--
--   Get-Content scripts\seed-oauth-test-client.sql | docker compose exec -T postgres psql -U sso -d sso
--
-- This assumes the tenant "acme" already exists (created via the app's normal tenant-creation
-- path used throughout Phase 2's manual testing). If you used a different tenant slug, change
-- the subquery below accordingly.
--
-- TEST CREDENTIALS (assistant-generated, for local testing only - never a real secret):
--   client_id:     acme-test-app
--   client_secret: azYOMTKrzKpKynj_VRi4Gaz_xKIiZ93s8vua46CTFY8
-- The row below stores only the SHA-256 hash of that secret (see Sha256ClientSecretHasherAdapter),
-- exactly like every other secret/token in this project - never the plaintext value itself.

INSERT INTO oauth_clients (
    id, tenant_id, client_id, client_secret_hash, name,
    redirect_uris, allowed_scopes, allowed_grant_types, status, created_at
)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM tenants WHERE slug = 'acme'),
    'acme-test-app',
    'cca95e8f912fdc9b8ec61e15ea96c3d545e6564b92626d03b370fea663e92fa6',
    'Acme Test App',
    'https://app.example.com/callback,http://localhost:4000/callback',
    'openid,profile,email',
    'AUTHORIZATION_CODE',
    'ACTIVE',
    now()
);

-- Phase 3.6: to manually exercise the Refresh Token grant (rotation + reuse detection) against
-- this same acme-test-app client, run the UPDATE below once to add the offline_access scope and
-- the REFRESH_TOKEN grant type to its already-seeded row - this does NOT change the client_id or
-- client_secret above, so the same credentials keep working for every existing manual test:
--
--   Get-Content scripts\enable-refresh-token-for-test-client.sql | docker compose exec -T postgres psql -U sso -d sso
--
-- (or paste the statement directly into `docker compose exec postgres psql -U sso -d sso`).
--
-- UPDATE oauth_clients
-- SET allowed_scopes = 'openid,profile,email,offline_access',
--     allowed_grant_types = 'AUTHORIZATION_CODE,REFRESH_TOKEN'
-- WHERE client_id = 'acme-test-app';
