package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.oauth.OAuthClientStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of an OAuth client row, scoped by {@code tenant_id} - mirrors {@link
 * UserJpaEntity}'s reasoning for keeping tenant scoping an explicit column rather than a managed
 * association.
 *
 * <p>{@code redirect_uris}, {@code allowed_scopes} and {@code allowed_grant_types} are each stored
 * as a single comma-separated {@code TEXT}/{@code VARCHAR} column rather than normalized into
 * their own join tables. This is a deliberate simplicity trade-off for this sub-phase: clients are
 * provisioned by hand via a single SQL {@code INSERT} for now (see {@code
 * architecture_decisions.md}), and a comma-separated column keeps that insert a one-liner per
 * client instead of needing several child-table inserts. Nothing about {@link
 * com.ssoplatform.idp.domain.oauth.OAuthClient}'s public shape (three {@code Set}s) depends on
 * this - the mapper is the only place that would need to change if a later phase ever needs to
 * query directly by an individual redirect URI or scope and normalizes these into real tables.
 */
@Entity
@Table(name = "oauth_clients")
public class OAuthClientJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "client_id", nullable = false, length = 128)
    private String clientId;

    /** {@code null} for a public client - see {@code OAuthClient#isPublic()}. Made nullable by
     * {@code V12__make_oauth_client_secret_hash_nullable.sql} (Device Authorization Grant phase). */
    @Column(name = "client_secret_hash", length = 255)
    private String clientSecretHash;

    @Column(name = "name", nullable = false, length = 150)
    private String name;

    @Column(name = "redirect_uris", nullable = false, columnDefinition = "TEXT")
    private String redirectUris;

    @Column(name = "allowed_scopes", nullable = false, length = 255)
    private String allowedScopes;

    @Column(name = "allowed_grant_types", nullable = false, length = 255)
    private String allowedGrantTypes;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    private OAuthClientStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected OAuthClientJpaEntity() {
        // required by JPA
    }

    public OAuthClientJpaEntity(
            UUID id,
            UUID tenantId,
            String clientId,
            String clientSecretHash,
            String name,
            String redirectUris,
            String allowedScopes,
            String allowedGrantTypes,
            OAuthClientStatus status,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.name = name;
        this.redirectUris = redirectUris;
        this.allowedScopes = allowedScopes;
        this.allowedGrantTypes = allowedGrantTypes;
        this.status = status;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecretHash() {
        return clientSecretHash;
    }

    public String getName() {
        return name;
    }

    public String getRedirectUris() {
        return redirectUris;
    }

    public String getAllowedScopes() {
        return allowedScopes;
    }

    public String getAllowedGrantTypes() {
        return allowedGrantTypes;
    }

    public OAuthClientStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
