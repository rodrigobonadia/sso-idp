-- Phase 3.6 manual-testing helper: enables the offline_access scope and the REFRESH_TOKEN grant
-- type on the already-seeded acme-test-app client (see scripts/seed-oauth-test-client.sql),
-- without changing its client_id or client_secret.
UPDATE oauth_clients
SET allowed_scopes = 'openid,profile,email,offline_access',
    allowed_grant_types = 'AUTHORIZATION_CODE,REFRESH_TOKEN'
WHERE client_id = 'acme-test-app';
