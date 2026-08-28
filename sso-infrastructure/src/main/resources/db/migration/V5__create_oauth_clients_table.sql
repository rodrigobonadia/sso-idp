CREATE TABLE oauth_clients (
    id                   UUID         PRIMARY KEY,
    tenant_id            UUID         NOT NULL REFERENCES tenants (id),
    client_id            VARCHAR(128) NOT NULL,
    client_secret_hash   VARCHAR(255) NOT NULL,
    name                 VARCHAR(150) NOT NULL,
    redirect_uris        TEXT         NOT NULL,
    allowed_scopes       VARCHAR(255) NOT NULL,
    allowed_grant_types  VARCHAR(255) NOT NULL,
    status               VARCHAR(30)  NOT NULL,
    created_at           TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_oauth_clients_client_id UNIQUE (client_id)
);

CREATE INDEX idx_oauth_clients_tenant_id ON oauth_clients (tenant_id);

COMMENT ON TABLE oauth_clients IS
    'Registered OAuth2/OIDC client applications, each scoped to exactly one tenant. Only confidential clients (with a client_secret_hash) are modeled so far - public/native clients are deferred, see architecture_decisions.md.';

-- NOTE: only a SHA-256 hash of the client secret is ever stored here, never the raw value - the
-- same reasoning as email_verification_tokens.token_hash and password_reset_tokens.token_hash: a
-- client secret is a high-entropy generated value (never a human-chosen one), so a fast,
-- unsalted hash is an appropriate and deliberate choice, not an oversight (see
-- Sha256ClientSecretHasherAdapter's Javadoc).
--
-- redirect_uris, allowed_scopes and allowed_grant_types are each stored as a single
-- comma-separated column rather than normalized into their own join tables - a deliberate
-- simplicity trade-off while clients are provisioned by hand via SQL (see
-- OAuthClientJpaEntity's Javadoc for the full reasoning and how to normalize this later if ever
-- needed).
