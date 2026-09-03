CREATE TABLE recovery_codes (
    id           UUID         PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users (id),
    code_hash    VARCHAR(255) NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL
);

CREATE INDEX idx_recovery_codes_user_id ON recovery_codes (user_id);

COMMENT ON TABLE recovery_codes IS
    'Single-use MFA recovery ("backup") codes, issued ten at a time when TOTP enrollment is confirmed (Phase 4.1). code_hash is a BCrypt hash (see BCryptRecoveryCodeHasherAdapter, RecoveryCodeHash) - unlike a password_reset_tokens.token_hash, it cannot be looked up by equality, so verifying a candidate means loading every unconsumed row for the user and checking each hash in turn.';
