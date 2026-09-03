CREATE TABLE mfa_challenges (
    id           UUID         PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users (id),
    tenant_id    UUID         NOT NULL REFERENCES tenants (id),
    token_hash   VARCHAR(255) NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_mfa_challenges_token_hash UNIQUE (token_hash)
);

CREATE INDEX idx_mfa_challenges_user_id ON mfa_challenges (user_id);

COMMENT ON TABLE mfa_challenges IS
    'Short-lived (5 minute), single-use tokens bridging the two HTTP calls of a two-step login once LoginUseCase finds an ACTIVE totp_credentials row for the user (Phase 4.1) - see MfaChallenge/LoginOutcome.MfaChallengeIssued. Structurally identical to password_reset_tokens plus tenant_id, since the second step has no other way to recover which tenant the original login attempt was scoped to.';
