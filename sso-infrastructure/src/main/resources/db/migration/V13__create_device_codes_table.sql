CREATE TABLE device_codes (
    id                  UUID         PRIMARY KEY,
    tenant_id           UUID         NOT NULL REFERENCES tenants (id),
    oauth_client_id     UUID         NOT NULL REFERENCES oauth_clients (id),
    device_code_hash    VARCHAR(255) NOT NULL,
    user_code           VARCHAR(16)  NOT NULL,
    scopes              VARCHAR(255) NOT NULL,
    status              VARCHAR(20)  NOT NULL,
    user_id             UUID         REFERENCES users (id),
    expires_at          TIMESTAMPTZ  NOT NULL,
    last_polled_at      TIMESTAMPTZ,
    redeemed_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_device_codes_device_code_hash UNIQUE (device_code_hash),
    CONSTRAINT uk_device_codes_user_code UNIQUE (user_code)
);

CREATE INDEX idx_device_codes_tenant_id ON device_codes (tenant_id);

COMMENT ON TABLE device_codes IS
    'Device authorization requests issued by POST /device_authorization (RFC 8628, Phase 3.9) for the urn:ietf:params:oauth:grant-type:device_code grant. Only device_code_hash is stored, never the plaintext device_code (see DeviceCode/Sha256VerificationTokenHasherAdapter); user_code is the short, human-typeable value entered at the verification page and IS stored as plaintext since it is deliberately low-entropy and meant to be looked up directly, never a secret (see UserCode). user_id is NULL until a user approves the request; last_polled_at/redeemed_at are NULL until the device first polls /token / successfully redeems the code.';

COMMENT ON COLUMN device_codes.status IS
    'One of PENDING, APPROVED, DENIED, REDEEMED - see DeviceCodeStatus for the meaning of each.';
