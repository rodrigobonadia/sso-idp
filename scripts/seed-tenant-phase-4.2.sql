-- Phase 4.2 manual test: provisions a fresh tenant to exercise the e-mail OTP MFA flow
-- end-to-end against a real, running app (docker compose up) - independent of tenants used
-- by earlier phases' manual testing, so this never depends on unknown local state and never
-- collides with it.
--
-- How to run it (PowerShell, from the project root, with `docker compose up` already running):
--
--   Get-Content scripts\seed-tenant-phase-4.2.sql | docker compose exec -T postgres psql -U sso -d sso
--
-- Tenant slug: acme-eotp-phase42 (subdomain for manual HTTP testing: acme-eotp-phase42.localhost)

INSERT INTO tenants (id, slug, name, status, created_at)
VALUES (gen_random_uuid(), 'acme-eotp-phase42', 'Acme Email OTP Phase 4.2 Test', 'ACTIVE', now())
ON CONFLICT (slug) DO NOTHING;
