CREATE TABLE resources (
    id            UUID        PRIMARY KEY,
    tenant_id     UUID        NOT NULL REFERENCES tenants (id),
    identifier    TEXT        NOT NULL,
    name          VARCHAR(150) NOT NULL,
    scopes        TEXT        NOT NULL,
    status        VARCHAR(30) NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,

    CONSTRAINT uk_resources_tenant_id_identifier UNIQUE (tenant_id, identifier)
);

CREATE INDEX idx_resources_tenant_id ON resources (tenant_id);

COMMENT ON TABLE resources IS
    'Registered API resource servers (RFC 8707 "resource"/audience) that Client Credentials tokens can be issued for, each scoped to exactly one tenant. Provisioned by hand via SQL for now, exactly like oauth_clients - see architecture_decisions.md.';

CREATE TABLE client_resource_authorizations (
    id                UUID        PRIMARY KEY,
    tenant_id         UUID        NOT NULL REFERENCES tenants (id),
    oauth_client_id   UUID        NOT NULL REFERENCES oauth_clients (id),
    resource_id       UUID        NOT NULL REFERENCES resources (id),
    granted_scopes    TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,

    CONSTRAINT uk_client_resource_authorizations_client_resource UNIQUE (oauth_client_id, resource_id)
);

CREATE INDEX idx_client_resource_authorizations_tenant_id ON client_resource_authorizations (tenant_id);
CREATE INDEX idx_client_resource_authorizations_oauth_client_id ON client_resource_authorizations (oauth_client_id);

COMMENT ON TABLE client_resource_authorizations IS
    'Authorizes exactly one oauth_client to request Client Credentials access tokens for exactly one resource, and defines the subset of that resource''s scopes the client may actually request - see ClientResourceAuthorization''s Javadoc. Provisioned by hand via SQL for now, exactly like oauth_clients and resources.';

-- NOTE: scopes and granted_scopes are each stored as a single comma-separated TEXT column rather
-- than normalized into their own join/child tables - the same deliberate simplicity trade-off
-- V5__create_oauth_clients_table.sql documents for oauth_clients' own multi-valued columns, while
-- both are still provisioned by hand via SQL (see ResourceJpaEntity's and
-- ClientResourceAuthorizationJpaEntity's Javadoc for the full reasoning).
