package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.resource.ResourceStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of an API resource (RFC 8707 "resource"/audience) row, scoped by {@code
 * tenant_id} - mirrors {@link OAuthClientJpaEntity}'s reasoning for keeping tenant scoping an
 * explicit column.
 *
 * <p>{@code scopes} is stored as a single comma-separated {@code TEXT} column, the same
 * deliberate simplicity trade-off {@link OAuthClientJpaEntity}'s Javadoc documents for its own
 * multi-valued columns, and for the same reason: resources are provisioned by hand via SQL for
 * now (see {@code architecture_decisions.md}).
 */
@Entity
@Table(name = "resources")
public class ResourceJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "identifier", nullable = false, columnDefinition = "TEXT")
    private String identifier;

    @Column(name = "name", nullable = false, length = 150)
    private String name;

    @Column(name = "scopes", nullable = false, columnDefinition = "TEXT")
    private String scopes;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private ResourceStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected ResourceJpaEntity() {
        // required by JPA
    }

    public ResourceJpaEntity(
            UUID id,
            UUID tenantId,
            String identifier,
            String name,
            String scopes,
            ResourceStatus status,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.identifier = identifier;
        this.name = name;
        this.scopes = scopes;
        this.status = status;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getIdentifier() {
        return identifier;
    }

    public String getName() {
        return name;
    }

    public String getScopes() {
        return scopes;
    }

    public ResourceStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
