CREATE TABLE password_reset_tokens (
    id           UUID PRIMARY KEY,
    user_id      UUID         NOT NULL REFERENCES users (id),
    token_hash   VARCHAR(255) NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_password_reset_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);

COMMENT ON TABLE password_reset_tokens IS
    'Single-use, time-limited tokens proving a user clicked the password-reset link sent to their e-mail address.';

-- NOTE: only the token's hash is ever stored here, never the raw value handed out in the
-- reset link - the same reason users.password_hash never stores a plaintext password. Kept as
-- its own table (rather than reusing email_verification_tokens) so the two kinds of token can
-- never be confused with one another at the persistence layer.
