CREATE TABLE totp_credentials (
    id                UUID         PRIMARY KEY,
    user_id           UUID         NOT NULL REFERENCES users (id),
    encrypted_secret  TEXT         NOT NULL,
    status            VARCHAR(20)  NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL,
    activated_at      TIMESTAMPTZ,

    CONSTRAINT uk_totp_credentials_user_id UNIQUE (user_id)
);

COMMENT ON TABLE totp_credentials IS
    'Each user''s TOTP (RFC 6238, Phase 4.1) second factor - at most one row per user, enforced by the unique constraint on user_id. encrypted_secret is always AES-256-GCM ciphertext (see AesGcmTotpSecretEncryptorAdapter), never a plaintext secret.';

COMMENT ON COLUMN totp_credentials.status IS
    'One of PENDING_ACTIVATION, ACTIVE - see TotpCredentialStatus. A PENDING_ACTIVATION row cannot satisfy a login challenge until confirmed with a real code.';
