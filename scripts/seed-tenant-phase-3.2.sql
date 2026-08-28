-- Phase 3.2 manual test: provisions a fresh tenant to exercise the signing-key generation and
-- JWKS endpoints end-to-end against a real, running app (docker compose up) - independent of the
-- "acme" tenant used by earlier phases' manual testing, so this never depends on unknown local
-- state and never collides with it.
--
-- How to run it (PowerShell, from the project root, with `docker compose up` already running):
--
--   Get-Content scripts\seed-tenant-phase-3.2.sql | docker compose exec -T postgres psql -U sso -d sso
--
-- Tenant slug: acme-signing-phase32 (subdomain for manual HTTP testing: acme-signing-phase32.localhost)

INSERT INTO tenants (id, slug, name, status, created_at)
VALUES (gen_random_uuid(), 'acme-signing-phase32', 'Acme Signing Phase 3.2 Test', 'ACTIVE', now())
ON CONFLICT (slug) DO NOTHING;
