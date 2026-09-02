-- given_name/family_name became required at registration (Phase 3.7, needed by GET /userinfo's
-- "profile" scope claims). Existing rows predate this requirement, so each column is added with
-- a placeholder DEFAULT to backfill them, then the DEFAULT is dropped so it can never mask a
-- missing value on a future INSERT - the application layer (PersonName) is the only thing
-- allowed to supply this value from now on.
ALTER TABLE users
    ADD COLUMN given_name  VARCHAR(100) NOT NULL DEFAULT 'Unknown',
    ADD COLUMN family_name VARCHAR(100) NOT NULL DEFAULT 'Unknown';

ALTER TABLE users
    ALTER COLUMN given_name DROP DEFAULT,
    ALTER COLUMN family_name DROP DEFAULT;

COMMENT ON COLUMN users.given_name IS 'OIDC given_name claim (OIDC Core 1.0, section 5.1), required at registration.';
COMMENT ON COLUMN users.family_name IS 'OIDC family_name claim (OIDC Core 1.0, section 5.1), required at registration.';
