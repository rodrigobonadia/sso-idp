-- Phase 3.8 manual-testing helper: Client Credentials grant (RFC 6749 section 4.4) with the
-- Resource/Audience model (RFC 8707) - see architecture_decisions.md for the design.
--
-- This is NOT a Flyway migration: it is not auto-run on `docker compose up`, so it will never
-- insert test data into a real deployment. Run it yourself, once, against your local Postgres,
-- with `docker compose up -d --build` already running (so the V11 migration has created the
-- resources / client_resource_authorizations tables).
--
-- How to run it (PowerShell, from the project root):
--
--   Get-Content scripts\seed-client-credentials-manual-test.sql | docker compose exec -T postgres psql -U sso -d sso
--
-- This assumes the tenant "acme" already exists (created via the app's normal tenant-creation
-- path used throughout Phase 2/3's manual testing). If you used a different tenant slug, change
-- the subqueries below accordingly.
--
-- TEST CREDENTIALS (assistant-generated, for local testing only - never a real secret):
--   client_id:     billing-service
--   client_secret: XMjPBwd3yrEhX1FiY4meyLpwhXHWFv7o_2ISLHTkaIs
-- The row below stores only the SHA-256 hash of that secret (see Sha256ClientSecretHasherAdapter),
-- exactly like scripts/seed-oauth-test-client.sql already does for acme-test-app.
--
-- Resource: https://api.example.com/orders, defining two scopes (orders:read, orders:write).
-- billing-service is authorized for that resource, but granted ONLY orders:read - so the manual
-- test plan below can exercise both the happy path (scope omitted -> orders:read issued) and the
-- invalid_scope rejection (explicitly requesting orders:write).

INSERT INTO oauth_clients (
    id, tenant_id, client_id, client_secret_hash, name,
    redirect_uris, allowed_scopes, allowed_grant_types, status, created_at
)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM tenants WHERE slug = 'acme'),
    'billing-service',
    'abc0d3bf2d827143c98ef80533d59ac59fe44384d5be49906549d6bcd724ca45',
    'Billing Service',
    'https://app.example.com/callback',
    'openid',
    'CLIENT_CREDENTIALS',
    'ACTIVE',
    now()
);

INSERT INTO resources (
    id, tenant_id, identifier, name, scopes, status, created_at
)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM tenants WHERE slug = 'acme'),
    'https://api.example.com/orders',
    'Orders API',
    'orders:read,orders:write',
    'ACTIVE',
    now()
);

INSERT INTO client_resource_authorizations (
    id, tenant_id, oauth_client_id, resource_id, granted_scopes, created_at
)
VALUES (
    gen_random_uuid(),
    (SELECT id FROM tenants WHERE slug = 'acme'),
    (SELECT id FROM oauth_clients WHERE client_id = 'billing-service'),
    (SELECT id FROM resources WHERE identifier = 'https://api.example.com/orders'),
    'orders:read',
    now()
);
