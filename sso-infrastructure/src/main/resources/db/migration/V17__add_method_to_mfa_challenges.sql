-- Phase 4.2 introduces a second MFA method (e-mail OTP) alongside TOTP, so an MfaChallenge must
-- now record which one it was issued for. Backfilled to 'TOTP' for any pre-existing rows (the only
-- method that existed before this migration) and the default is then dropped so every future
-- insert must supply it explicitly - the domain always does (see MfaChallenge.issue).
ALTER TABLE mfa_challenges ADD COLUMN method VARCHAR(20) NOT NULL DEFAULT 'TOTP';
ALTER TABLE mfa_challenges ALTER COLUMN method DROP DEFAULT;

COMMENT ON COLUMN mfa_challenges.method IS
    'One of TOTP, EMAIL_OTP - see MfaMethod. Decided once at issuance time based on whichever credential was active for the user; never re-derived at verification time.';
