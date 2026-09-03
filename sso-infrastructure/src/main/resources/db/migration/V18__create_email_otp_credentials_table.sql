CREATE TABLE email_otp_credentials (
    id            UUID         PRIMARY KEY,
    user_id       UUID         NOT NULL REFERENCES users (id),
    status        VARCHAR(20)  NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL,
    activated_at  TIMESTAMPTZ,

    CONSTRAINT uk_email_otp_credentials_user_id UNIQUE (user_id)
);

COMMENT ON TABLE email_otp_credentials IS
    'Each user''s e-mail OTP (Phase 4.2) second factor - at most one row per user, enforced by the unique constraint on user_id. Unlike totp_credentials, there is no secret column here at all: an e-mail OTP code is a fresh random value generated and hashed anew every time one is needed (see email_otp_codes), never derived from anything stored on this row.';

COMMENT ON COLUMN email_otp_credentials.status IS
    'One of PENDING_ACTIVATION, ACTIVE - see EmailOtpCredentialStatus. A PENDING_ACTIVATION row cannot satisfy a login challenge until confirmed with a real code sent to the user''s registered address.';
