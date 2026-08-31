package com.ssoplatform.idp.domain.oauth;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * A registered OAuth2/OIDC client application, always scoped to exactly one {@link
 * com.ssoplatform.idp.domain.tenant.Tenant} - mirroring {@link
 * com.ssoplatform.idp.domain.user.User}'s tenant scoping, and chosen for the same architectural
 * reason: the web layer already resolves the active tenant from the request's subdomain (Phase
 * 2.1), so a client usable across tenants would have no reliable way to be looked up.
 *
 * <p>Only <b>confidential</b> clients are modeled so far (a {@link #clientSecretHash} is always
 * present): public clients (SPAs, native/mobile apps with no client secret) are deliberately
 * deferred - see {@code architecture_decisions.md}. Every client requires PKCE regardless of type,
 * per the same decision - so this entity does not carry a "requires PKCE" flag at all; the
 * {@code /authorize} and {@code /token} endpoints being built in later Phase 3 sub-phases enforce
 * PKCE unconditionally for every request, rather than this being a per-client, disable-able
 * setting.
 *
 * <p>{@link #allowedScopes} and {@link #allowedGrantTypes} are both intersected against what a
 * given request actually asks for - see {@link #supportsScope(String)} and {@link
 * #supportsGrantType(GrantType)} - so a client provisioned for only {@code AUTHORIZATION_CODE} and
 * {@code openid,profile} cannot be used for a grant or scope it was never granted, even though the
 * platform as a whole may support more of each over time.
 */
public final class OAuthClient {

    /** The only scopes the platform recognizes at all, regardless of what any client is allowed. */
    public static final Set<String> SUPPORTED_SCOPES = Set.of("openid", "profile", "email", "offline_access");

    private final OAuthClientId id;
    private final TenantId tenantId;
    private final ClientId clientId;
    private ClientSecretHash clientSecretHash;
    private String name;
    private final Set<RedirectUri> redirectUris;
    private final Set<String> allowedScopes;
    private final Set<GrantType> allowedGrantTypes;
    private OAuthClientStatus status;
    private final Instant createdAt;

    private OAuthClient(
            OAuthClientId id,
            TenantId tenantId,
            ClientId clientId,
            ClientSecretHash clientSecretHash,
            String name,
            Set<RedirectUri> redirectUris,
            Set<String> allowedScopes,
            Set<GrantType> allowedGrantTypes,
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

    /** Registers a brand-new, active client. */
    public static OAuthClient register(
            TenantId tenantId,
            ClientId clientId,
            ClientSecretHash clientSecretHash,
            String name,
            Set<RedirectUri> redirectUris,
            Set<String> allowedScopes,
            Set<GrantType> allowedGrantTypes) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(clientSecretHash, "clientSecretHash must not be null");
        return new OAuthClient(
                OAuthClientId.generate(),
                tenantId,
                clientId,
                clientSecretHash,
                validateName(name),
                validateRedirectUris(redirectUris),
                validateScopes(allowedScopes),
                validateGrantTypes(allowedGrantTypes),
                OAuthClientStatus.ACTIVE,
                Instant.now());
    }

    /** Reconstitutes a client that already exists (used by persistence adapters). */
    public static OAuthClient reconstitute(
            OAuthClientId id,
            TenantId tenantId,
            ClientId clientId,
            ClientSecretHash clientSecretHash,
            String name,
            Set<RedirectUri> redirectUris,
            Set<String> allowedScopes,
            Set<GrantType> allowedGrantTypes,
            OAuthClientStatus status,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(clientSecretHash, "clientSecretHash must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new OAuthClient(
                id,
                tenantId,
                clientId,
                clientSecretHash,
                validateName(name),
                validateRedirectUris(redirectUris),
                validateScopes(allowedScopes),
                validateGrantTypes(allowedGrantTypes),
                status,
                createdAt);
    }

    private static String validateName(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new IllegalArgumentException("OAuth client name must not be blank");
        }
        return candidate.trim();
    }

    private static Set<RedirectUri> validateRedirectUris(Set<RedirectUri> candidate) {
        Objects.requireNonNull(candidate, "redirectUris must not be null");
        if (candidate.isEmpty()) {
            throw new IllegalArgumentException("An OAuth client must have at least one redirect URI");
        }
        return Set.copyOf(candidate);
    }

    private static Set<String> validateScopes(Set<String> candidate) {
        Objects.requireNonNull(candidate, "allowedScopes must not be null");
        if (candidate.isEmpty()) {
            throw new IllegalArgumentException("An OAuth client must have at least one allowed scope");
        }
        for (String scope : candidate) {
            if (!SUPPORTED_SCOPES.contains(scope)) {
                throw new IllegalArgumentException(
                        "Scope '" + scope + "' is not one of the platform's supported scopes " + SUPPORTED_SCOPES);
            }
        }
        return Set.copyOf(candidate);
    }

    private static Set<GrantType> validateGrantTypes(Set<GrantType> candidate) {
        Objects.requireNonNull(candidate, "allowedGrantTypes must not be null");
        if (candidate.isEmpty()) {
            throw new IllegalArgumentException("An OAuth client must have at least one allowed grant type");
        }
        return Set.copyOf(candidate);
    }

    public void rename(String newName) {
        this.name = validateName(newName);
    }

    public void rotateSecret(ClientSecretHash newClientSecretHash) {
        this.clientSecretHash = Objects.requireNonNull(newClientSecretHash, "newClientSecretHash must not be null");
    }

    public void disable() {
        if (status == OAuthClientStatus.DISABLED) {
            throw new OAuthClientStateException("OAuth client '" + clientId + "' is already disabled");
        }
        this.status = OAuthClientStatus.DISABLED;
    }

    public void enable() {
        if (status != OAuthClientStatus.DISABLED) {
            throw new OAuthClientStateException("OAuth client '" + clientId + "' is not disabled");
        }
        this.status = OAuthClientStatus.ACTIVE;
    }

    public boolean isUsable() {
        return status == OAuthClientStatus.ACTIVE;
    }

    /** Exact-match lookup against the registered redirect URIs - see the class Javadoc for why this is never a prefix/pattern match. */
    public boolean isRedirectUriRegistered(RedirectUri candidate) {
        Objects.requireNonNull(candidate, "candidate must not be null");
        return redirectUris.contains(candidate);
    }

    public boolean supportsScope(String scope) {
        return allowedScopes.contains(scope);
    }

    public boolean supportsGrantType(GrantType grantType) {
        return allowedGrantTypes.contains(grantType);
    }

    public OAuthClientId id() {
        return id;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public ClientId clientId() {
        return clientId;
    }

    public ClientSecretHash clientSecretHash() {
        return clientSecretHash;
    }

    public String name() {
        return name;
    }

    public Set<RedirectUri> redirectUris() {
        return Set.copyOf(redirectUris);
    }

    public Set<String> allowedScopes() {
        return Set.copyOf(allowedScopes);
    }

    public Set<GrantType> allowedGrantTypes() {
        return new LinkedHashSet<>(allowedGrantTypes);
    }

    public OAuthClientStatus status() {
        return status;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OAuthClient that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
