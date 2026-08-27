package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.user.UserStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of a user row, scoped by {@code tenant_id}. This column (rather than a
 * managed {@code @ManyToOne} association) is a deliberate choice: it keeps the multi-tenancy
 * boundary explicit and is exactly the column Row Level Security policies (Phase 5) will key
 * their tenant-isolation predicate on.
 */
@Entity
@Table(name = "users")
public class UserJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "email", nullable = false, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private UserStatus status;

    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected UserJpaEntity() {
        // required by JPA
    }

    public UserJpaEntity(
            UUID id,
            UUID tenantId,
            String email,
            String passwordHash,
            UserStatus status,
            int failedLoginAttempts,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.email = email;
        this.passwordHash = passwordHash;
        this.status = status;
        this.failedLoginAttempts = failedLoginAttempts;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public UserStatus getStatus() {
        return status;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
