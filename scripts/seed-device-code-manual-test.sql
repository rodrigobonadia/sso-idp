-- Phase 3.9 manual-testing helper: Device Authorization Grant (RFC 8628).
--
-- This is NOT a Flyway migration: it is not auto-run on `docker compose up`, so it will never
-- insert test data into a real deployment. Run it yourself, once, against your local Postgres,
-- with `docker compose up -d --build` already running (so the V12/V13 migrations have run).
--
-- How to run it (PowerShell, from the project root):
--
--   Get-Content scripts\seed-device-code-manual-test.sql | docker compose exec -T postgres psql -U sso -d sso
--
-- This assumes the tenant "acme" already exists (created via the app's normal tenant-creation
-- path used throughout Phase 2/3's manual testing). If you used a different tenant slug, change
-- the subqueries below accordingly.
--
-- Seeds TWO clients, since Phase 3.9 introduces genuine public-client support and both need to be
-- exercised: a CONFIDENTIAL one (authenticates at /device_authorization and /token with HTTP
-- Basic, exactly like every other grant) and a PUBLIC one (authenticates with a bare client_id
-- body param, no secret at all - the market-standard case for this grant, e.g. a smart TV or a
-- CLI tool). Neither registers a redirect_uri (empty string) - meaningless for this grant, since
-- neither ever redirects a browser anywhere; see OAuthClient's Javadoc.
--
-- TEST CREDENTIALS (assistant-generated, for local testing only - never a real secret):
--   client_id:     tv-app-confidential
--   client_secret: IBmFaRaazqp8fj8YeSPvyq2fzZ1stSVZzTzmP8UeccU
-- The row below stores only the SHA-256 hash of that secret (see Sha256ClientSecretHasherAdapter),
-- exactly like scripts/seed-oauth-test-client.sql already does for acme-test-app.
--
--   client_id:     tv-app-public   (no secret - client_secret_hash is NULL, a public client)

INSERT INTO oauth_clients (
    id, tenant_id, client_id, client_secret_hash, name,
    redirect_uris, allowed_scopes, allowed_grant_types, status, created_at
)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM tenants WHERE slug = 'acme'),
    'tv-app-confidential',
    'b9a1a4dd62ac7d4e5a56eb35a9b7ec7e2b10515b9af27768d9845a34568f6e28',
    'Smart TV App (Confidential)',
    '',
    'openid,profile',
    'DEVICE_CODE',
    'ACTIVE',
    now()
);

INSERT INTO oauth_clients (
    id, tenant_id, client_id, client_secret_hash, name,
    redirect_uris, allowed_scopes, allowed_grant_types, status, created_at
)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM tenants WHERE slug = 'acme'),
    'tv-app-public',
    NULL,
    'Smart TV App (Public)',
    '',
    'openid,profile',
    'DEVICE_CODE',
    'ACTIVE',
    now()
);
