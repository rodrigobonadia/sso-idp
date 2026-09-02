ALTER TABLE oauth_clients ALTER COLUMN client_secret_hash DROP NOT NULL;

COMMENT ON COLUMN oauth_clients.client_secret_hash IS
    'SHA-256 hash of the client secret, or NULL for a public client (one that cannot securely hold a secret - e.g. a CLI tool using the Device Authorization Grant, Phase 3.9). See OAuthClient.isConfidential()/isPublic().';
