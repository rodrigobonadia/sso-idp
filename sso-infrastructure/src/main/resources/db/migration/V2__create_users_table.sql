CREATE TABLE users (
    id                     UUID PRIMARY KEY,
    tenant_id              UUID         NOT NULL REFERENCES tenants (id),
    email                  VARCHAR(255) NOT NULL,
    password_hash          VARCHAR(255) NOT NULL,
    status                 VARCHAR(30)  NOT NULL,
    failed_login_attempts  INT          NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ  NOT NULL,

    CONSTRAINT uk_users_tenant_email UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant_id ON users (tenant_id);
CREATE INDEX idx_users_status ON users (status);

COMMENT ON TABLE users IS 'User accounts, always scoped to a tenant via tenant_id.';

-- NOTE (multi-tenancy isolation): every UserRepository query in sso-application is already
-- scoped by tenant_id at the application layer. Row Level Security policies that enforce this
-- isolation directly at the database level (as a defense-in-depth measure, keyed off a
-- `app.current_tenant_id` session variable set per request) are intentionally deferred to
-- Phase 5 of the roadmap, once the web layer has a request-scoped tenant context to set that
-- variable from. Introducing RLS before that context exists would silently return zero rows
-- instead of failing loudly, which is worse than not having it yet.
