package com.ssoplatform.idp.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of a {@code (client, resource)} authorization row - the join between {@link
 * OAuthClientJpaEntity} and {@link ResourceJpaEntity}, carrying the granted-scopes subset for that
 * pair (see {@code ClientResourceAuthorization}'s Javadoc). {@code granted_scopes} is a
 * comma-separated {@code TEXT} column, the same encoding {@link OAuthClientJpaEntity} and {@link
 * ResourceJpaEntity} already use for their own multi-valued columns.
 */
@Entity
@Table(name = "client_resource_authorizations")
public class ClientResourceAuthorizationJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "oauth_client_id", nullable = false)
    private UUID oauthClientId;

    @Column(name = "resource_id", nullable = false)
    private UUID resourceId;

    @Column(name = "granted_scopes", nullable = false, columnDefinition = "TEXT")
    private String grantedScopes;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected ClientResourceAuthorizationJpaEntity() {
        // required by JPA
    }

    public ClientResourceAuthorizationJpaEntity(
            UUID id, UUID tenantId, UUID oauthClientId, UUID resourceId, String grantedScopes, Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.resourceId = resourceId;
        this.grantedScopes = grantedScopes;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public UUID getOauthClientId() {
        return oauthClientId;
    }

    public UUID getResourceId() {
        return resourceId;
    }

    public String getGrantedScopes() {
        return grantedScopes;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
