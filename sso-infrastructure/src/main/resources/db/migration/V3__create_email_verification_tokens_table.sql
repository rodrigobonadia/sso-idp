CREATE TABLE email_verification_tokens (
    id           UUID PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users (id),
    token_hash   VARCHAR(255) NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_email_verification_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens (user_id);

COMMENT ON TABLE email_verification_tokens IS
    'Single-use, time-limited tokens proving a user clicked the link sent to their e-mail address.';

-- NOTE: only the token's hash is ever stored here, never the raw value handed out in the
-- verification link - the same reason users.password_hash never stores a plaintext password.
