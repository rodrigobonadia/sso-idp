package com.ssoplatform.idp.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of a device-authorization-request row (RFC 8628). Looked up two different
 * ways by two different callers - see {@code DeviceCodeJpaRepository} - mirroring {@link
 * AuthorizationCodeJpaEntity}'s single-use-token shape for {@code device_code_hash}, plus a second
 * lookup key, {@code user_code}, that is deliberately stored as PLAINTEXT (not hashed): it is a
 * low-entropy, human-typed value meant to be looked up directly by the verification page, never a
 * secret - see {@code UserCode}'s Javadoc.
 *
 * <p>{@code scopes} is a single comma-separated column, the same simplicity trade-off {@code
 * OAuthClientJpaEntity} documents. {@code user_id} is nullable (unset until a user approves the
 * request); {@code last_polled_at}/{@code redeemed_at} are nullable for the same reason {@code
 * consumed_at} is on {@link AuthorizationCodeJpaEntity}.
 */
@Entity
@Table(name = "device_codes")
public class DeviceCodeJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "oauth_client_id", nullable = false)
    private UUID oauthClientId;

    @Column(name = "device_code_hash", nullable = false, length = 255)
    private String deviceCodeHash;

    @Column(name = "user_code", nullable = false, length = 16)
    private String userCode;

    @Column(name = "scopes", nullable = false, length = 255)
    private String scopes;

    @Column(name = "status", nullable = false, length = 20)
    private String status;

    @Column(name = "user_id")
    private UUID userId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "last_polled_at")
    private Instant lastPolledAt;

    @Column(name = "redeemed_at")
    private Instant redeemedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected DeviceCodeJpaEntity() {
        // required by JPA
    }

    public DeviceCodeJpaEntity(
            UUID id,
            UUID tenantId,
            UUID oauthClientId,
            String deviceCodeHash,
            String userCode,
            String scopes,
            String status,
            UUID userId,
            Instant expiresAt,
            Instant lastPolledAt,
            Instant redeemedAt,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.deviceCodeHash = deviceCodeHash;
        this.userCode = userCode;
        this.scopes = scopes;
        this.status = status;
        this.userId = userId;
        this.expiresAt = expiresAt;
        this.lastPolledAt = lastPolledAt;
        this.redeemedAt = redeemedAt;
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

    public String getDeviceCodeHash() {
        return deviceCodeHash;
    }

    public String getUserCode() {
        return userCode;
    }

    public String getScopes() {
        return scopes;
    }

    public String getStatus() {
        return status;
    }

    public UUID getUserId() {
        return userId;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getLastPolledAt() {
        return lastPolledAt;
    }

    public Instant getRedeemedAt() {
        return redeemedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
