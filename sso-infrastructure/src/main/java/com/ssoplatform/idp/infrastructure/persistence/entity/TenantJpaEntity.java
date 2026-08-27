package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.tenant.TenantStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of a tenant row. Deliberately separate from the {@code Tenant} domain
 * entity: this class only carries persistence concerns (column mapping) and is translated
 * to/from the domain entity by {@code TenantEntityMapper}, so that domain objects are never
 * annotated with JPA and never leak past the infrastructure layer.
 */
@Entity
@Table(name = "tenants")
public class TenantJpaEntity {

    @Id
    private UUID id;

    @Column(name = "slug", nullable = false, unique = true, length = 63)
    private String slug;

    @Column(name = "name", nullable = false, length = 150)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private TenantStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected TenantJpaEntity() {
        // required by JPA
    }

    public TenantJpaEntity(UUID id, String slug, String name, TenantStatus status, Instant createdAt) {
        this.id = id;
        this.slug = slug;
        this.name = name;
        this.status = status;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public String getSlug() {
        return slug;
    }

    public String getName() {
        return name;
    }

    public TenantStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
