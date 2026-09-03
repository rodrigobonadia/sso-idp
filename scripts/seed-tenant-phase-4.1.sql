-- Phase 4.1 manual test: provisions a fresh tenant to exercise the TOTP MFA flow end-to-end
-- against a real, running app (docker compose up) - independent of tenants used by earlier
-- phases' manual testing, so this never depends on unknown local state and never collides
-- with it.
--
-- How to run it (PowerShell, from the project root, with `docker compose up` already running):
--
--   Get-Content scripts\seed-tenant-phase-4.1.sql | docker compose exec -T postgres psql -U sso -d sso
--
-- Tenant slug: acme-mfa-phase41 (subdomain for manual HTTP testing: acme-mfa-phase41.localhost)

INSERT INTO tenants (id, slug, name, status, created_at)
VALUES (gen_random_uuid(), 'acme-mfa-phase41', 'Acme MFA Phase 4.1 Test', 'ACTIVE', now())
ON CONFLICT (slug) DO NOTHING;
