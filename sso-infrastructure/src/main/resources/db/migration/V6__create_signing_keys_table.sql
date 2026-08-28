CREATE TABLE signing_keys (
    id                      UUID         PRIMARY KEY,
    tenant_id               UUID         NOT NULL REFERENCES tenants (id),
    kid                     VARCHAR(64)  NOT NULL,
    algorithm               VARCHAR(20)  NOT NULL,
    public_key              TEXT         NOT NULL,
    encrypted_private_key   TEXT         NOT NULL,
    status                  VARCHAR(20)  NOT NULL,
    created_at              TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_signing_keys_kid UNIQUE (kid)
);

CREATE INDEX idx_signing_keys_tenant_id ON signing_keys (tenant_id);

-- At most one CURRENT key per tenant at any time - GenerateSigningKeyUseCase always retires the
-- previous current key (if any) before saving a new one, and this partial unique index makes that
-- invariant hold at the database level too, not just in application code.
CREATE UNIQUE INDEX uk_signing_keys_tenant_current ON signing_keys (tenant_id) WHERE status = 'CURRENT';

COMMENT ON TABLE signing_keys IS
    'RSA signing key pairs for OAuth2/OIDC token signing (RS256), scoped per tenant. Exactly one CURRENT key per tenant is used to sign new tokens; RETIRED keys are kept (and still published via JWKS) purely so tokens already issued under them remain verifiable. The private key is stored encrypted (AES-256-GCM, see AesGcmPrivateKeyEncryptorAdapter) - never in plaintext.';
