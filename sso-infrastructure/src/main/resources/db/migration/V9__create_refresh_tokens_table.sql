CREATE TABLE refresh_tokens (
    id                  UUID         PRIMARY KEY,
    family_id           UUID         NOT NULL,
    tenant_id           UUID         NOT NULL REFERENCES tenants (id),
    oauth_client_id     UUID         NOT NULL REFERENCES oauth_clients (id),
    user_id             UUID         NOT NULL REFERENCES users (id),
    token_hash          VARCHAR(255) NOT NULL,
    scopes              VARCHAR(255) NOT NULL,
    status              VARCHAR(20)  NOT NULL,
    family_expires_at   TIMESTAMPTZ  NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_refresh_tokens_token_hash UNIQUE (token_hash)
);

CREATE INDEX idx_refresh_tokens_tenant_id ON refresh_tokens (tenant_id);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens (family_id);

COMMENT ON TABLE refresh_tokens IS
    'Rotating refresh tokens issued by POST /token (Phase 3.6) for the authorization_code grant (when offline_access is granted) and redeemed - and rotated - via grant_type=refresh_token. Only token_hash is stored, never the plaintext value (see RefreshToken/Sha256VerificationTokenHasherAdapter). family_id groups every token descended from one original login into a single rotation chain sharing one fixed family_expires_at, computed once and copied unchanged onto every rotated descendant; presenting an already-ROTATED or already-REVOKED token is treated as a reuse/theft signal and revokes the whole family (see RefreshToken/TokenUseCase).';

COMMENT ON COLUMN refresh_tokens.status IS
    'One of ACTIVE, ROTATED, REVOKED - see RefreshTokenStatus for the meaning of each.';
