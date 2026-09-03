CREATE TABLE email_otp_codes (
    id                UUID         PRIMARY KEY,
    user_id           UUID         NOT NULL REFERENCES users (id),
    purpose           VARCHAR(30)  NOT NULL,
    mfa_challenge_id  UUID         REFERENCES mfa_challenges (id),
    code_hash         VARCHAR(255) NOT NULL,
    expires_at        TIMESTAMPTZ  NOT NULL,
    consumed_at       TIMESTAMPTZ,
    failed_attempts   INTEGER      NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ  NOT NULL
);

CREATE INDEX idx_email_otp_codes_user_id_purpose ON email_otp_codes (user_id, purpose);
CREATE UNIQUE INDEX uk_email_otp_codes_mfa_challenge_id ON email_otp_codes (mfa_challenge_id) WHERE mfa_challenge_id IS NOT NULL;

COMMENT ON TABLE email_otp_codes IS
    'Single, short-lived e-mail OTP code instances (Phase 4.2) - either confirming enrollment (purpose = ENROLLMENT_CONFIRMATION, mfa_challenge_id null) or satisfying one specific login challenge (purpose = LOGIN_CHALLENGE, mfa_challenge_id set - see EmailOtpCode, MfaChallenge). code_hash is a BCrypt hash (see BCryptEmailOtpCodeHasherAdapter), like recovery_codes.code_hash, not a token_hash-style SHA-256 digest - a candidate cannot be looked up by equality.';

COMMENT ON COLUMN email_otp_codes.failed_attempts IS
    'Wrong verification attempts against this specific code. Once it reaches EmailOtpCode.MAX_FAILED_ATTEMPTS (5), the code is permanently dead even if not yet time-expired - see EmailOtpCode''s Javadoc for why an e-mailed static code needs this and a rotating TOTP code does not.';
