CREATE TABLE authorization_codes (
    id                  UUID         PRIMARY KEY,
    tenant_id           UUID         NOT NULL REFERENCES tenants (id),
    oauth_client_id     UUID         NOT NULL REFERENCES oauth_clients (id),
    user_id             UUID         NOT NULL REFERENCES users (id),
    code_hash           VARCHAR(255) NOT NULL,
    redirect_uri        TEXT         NOT NULL,
    scopes              VARCHAR(255) NOT NULL,
    code_challenge      VARCHAR(128) NOT NULL,
    expires_at          TIMESTAMPTZ  NOT NULL,
    consumed_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_authorization_codes_code_hash UNIQUE (code_hash)
);

CREATE INDEX idx_authorization_codes_tenant_id ON authorization_codes (tenant_id);

COMMENT ON TABLE authorization_codes IS
    'Single-use, short-lived authorization codes issued by GET /authorize (Phase 3.3) for the Authorization Code + PKCE grant, redeemed by POST /token (Phase 3.4, not yet built). Only code_hash is stored, never the plaintext code (see AuthorizationCode/Sha256VerificationTokenHasherAdapter) - exactly like the email-verification and password-reset token tables.';
