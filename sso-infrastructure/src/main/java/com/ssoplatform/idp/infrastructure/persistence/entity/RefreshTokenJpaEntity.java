package com.ssoplatform.idp.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of a refresh-token row. Looked up by {@code token_hash} - see {@code
 * AuthorizationCodeJpaEntity} for the identical "single-use, high-entropy token" shape this
 * mirrors, and {@code family_id} - see {@code RefreshTokenJpaRepository#findAllByFamilyId} - for
 * the reuse-detection sweep.
 *
 * <p>{@code scopes} is stored as a single comma-separated column, the same simplicity trade-off
 * {@code AuthorizationCodeJpaEntity} makes for the same reason - a token's scopes are only ever
 * read back whole.
 *
 * <p>{@code status} is stored as its enum name ({@code ACTIVE}/{@code ROTATED}/{@code REVOKED})
 * rather than an ordinal, so the column stays meaningful if {@code RefreshTokenStatus} is ever
 * reordered.
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenJpaEntity {

    @Id
    private UUID id;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "oauth_client_id", nullable = false)
    private UUID oauthClientId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "token_hash", nullable = false, length = 255)
    private String tokenHash;

    @Column(name = "scopes", nullable = false, length = 255)
    private String scopes;

    @Column(name = "status", nullable = false, length = 20)
    private String status;

    @Column(name = "family_expires_at", nullable = false)
    private Instant familyExpiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected RefreshTokenJpaEntity() {
        // required by JPA
    }

    public RefreshTokenJpaEntity(
            UUID id,
            UUID familyId,
            UUID tenantId,
            UUID oauthClientId,
            UUID userId,
            String tokenHash,
            String scopes,
            String status,
            Instant familyExpiresAt,
            Instant createdAt) {
        this.id = id;
        this.familyId = familyId;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.scopes = scopes;
        this.status = status;
        this.familyExpiresAt = familyExpiresAt;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getFamilyId() {
        return familyId;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public UUID getOauthClientId() {
        return oauthClientId;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public String getScopes() {
        return scopes;
    }

    public String getStatus() {
        return status;
    }

    public Instant getFamilyExpiresAt() {
        return familyExpiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
