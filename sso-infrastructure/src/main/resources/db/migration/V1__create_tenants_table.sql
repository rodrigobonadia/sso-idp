CREATE TABLE tenants (
    id          UUID PRIMARY KEY,
    slug        VARCHAR(63)  NOT NULL,
    name        VARCHAR(150) NOT NULL,
    status      VARCHAR(20)  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_tenants_slug UNIQUE (slug)
);

CREATE INDEX idx_tenants_status ON tenants (status);

COMMENT ON TABLE tenants IS 'Isolated organizations on the platform. Unit of isolation for multi-tenancy.';
