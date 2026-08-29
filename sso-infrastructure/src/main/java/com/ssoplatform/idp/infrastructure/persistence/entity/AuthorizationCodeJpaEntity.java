package com.ssoplatform.idp.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of an authorization-code row. Looked up by {@code code_hash} - see {@code
 * PasswordResetTokenJpaEntity} for the identical "single-use, high-entropy token" shape this
 * mirrors.
 *
 * <p>{@code scopes} is stored as a single comma-separated column, the same simplicity trade-off
 * {@code OAuthClientJpaEntity} documents for its own scope/grant-type columns - a code's scopes are
 * only ever read back whole (never queried by an individual scope value), so a join table would add
 * nothing here.
 *
 * <p>{@code nonce} is nullable (added by {@code V8__add_nonce_to_authorization_codes_table.sql},
 * Phase 3.4) - see {@code AuthorizationCode}'s Javadoc for why it is optional.
 */
@Entity
@Table(name = "authorization_codes")
public class AuthorizationCodeJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "oauth_client_id", nullable = false)
    private UUID oauthClientId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "code_hash", nullable = false, length = 255)
    private String codeHash;

    @Column(name = "redirect_uri", nullable = false, columnDefinition = "TEXT")
    private String redirectUri;

    @Column(name = "scopes", nullable = false, length = 255)
    private String scopes;

    @Column(name = "code_challenge", nullable = false, length = 128)
    private String codeChallenge;

    @Column(name = "nonce")
    private String nonce;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected AuthorizationCodeJpaEntity() {
        // required by JPA
    }

    public AuthorizationCodeJpaEntity(
            UUID id,
            UUID tenantId,
            UUID oauthClientId,
            UUID userId,
            String codeHash,
            String redirectUri,
            String scopes,
            String codeChallenge,
            String nonce,
            Instant expiresAt,
            Instant consumedAt,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.userId = userId;
        this.codeHash = codeHash;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.codeChallenge = codeChallenge;
        this.nonce = nonce;
        this.expiresAt = expiresAt;
        this.consumedAt = consumedAt;
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

    public UUID getUserId() {
        return userId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScopes() {
        return scopes;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public String getNonce() {
        return nonce;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
