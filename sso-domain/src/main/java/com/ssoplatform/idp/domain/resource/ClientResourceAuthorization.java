package com.ssoplatform.idp.domain.resource;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * Authorizes exactly one {@link com.ssoplatform.idp.domain.oauth.OAuthClient} to request Client
 * Credentials access tokens (RFC 6749 section 4.4) for exactly one {@link Resource}, and defines
 * the subset of that resource's {@link Resource#scopes()} the client may actually request -
 * mirroring how Auth0/Okta model "which permissions of this API is this machine-to-machine
 * application granted", rather than an all-or-nothing "authorized for the resource" flag.
 *
 * <p>{@link #grantedScopes} is validated only for basic shape here (non-empty, no blank/whitespace
 * entries) - NOT as a subset of {@link Resource#scopes()}, since that would require loading the
 * {@code Resource} aggregate from here, which a domain object must not depend on. {@code
 * TokenUseCase} is responsible for the cross-aggregate defense-in-depth check that every granted
 * scope is still one the resource actually defines, at the point a token is issued - see its
 * Javadoc.
 *
 * <p>Provisioned by hand via SQL/seed data for now, exactly like {@link
 * com.ssoplatform.idp.domain.oauth.OAuthClient} and {@link Resource} - so, deliberately, there is
 * no {@code revoke()}/lifecycle here yet: removing an authorization is a row deletion at the SQL
 * level until an admin console (Phase 6) manages this instead.
 */
public final class ClientResourceAuthorization {

    private final ClientResourceAuthorizationId id;
    private final TenantId tenantId;
    private final OAuthClientId oauthClientId;
    private final ResourceId resourceId;
    private final Set<String> grantedScopes;
    private final Instant createdAt;

    private ClientResourceAuthorization(
            ClientResourceAuthorizationId id,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            ResourceId resourceId,
            Set<String> grantedScopes,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.resourceId = resourceId;
        this.grantedScopes = grantedScopes;
        this.createdAt = createdAt;
    }

    /** Creates a brand-new authorization. */
    public static ClientResourceAuthorization authorize(
            TenantId tenantId, OAuthClientId oauthClientId, ResourceId resourceId, Set<String> grantedScopes) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(resourceId, "resourceId must not be null");
        return new ClientResourceAuthorization(
                ClientResourceAuthorizationId.generate(),
                tenantId,
                oauthClientId,
                resourceId,
                validateGrantedScopes(grantedScopes),
                Instant.now());
    }

    /** Reconstitutes an authorization that already exists (used by persistence adapters). */
    public static ClientResourceAuthorization reconstitute(
            ClientResourceAuthorizationId id,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            ResourceId resourceId,
            Set<String> grantedScopes,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(resourceId, "resourceId must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new ClientResourceAuthorization(
                id, tenantId, oauthClientId, resourceId, validateGrantedScopes(grantedScopes), createdAt);
    }

    private static Set<String> validateGrantedScopes(Set<String> candidate) {
        Objects.requireNonNull(candidate, "grantedScopes must not be null");
        if (candidate.isEmpty()) {
            throw new IllegalArgumentException("A client-resource authorization must grant at least one scope");
        }
        for (String scope : candidate) {
            if (scope == null || scope.isBlank()) {
                throw new IllegalArgumentException("A granted scope must not be blank");
            }
            if (scope.chars().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException("Granted scope '" + scope + "' must not contain whitespace");
            }
        }
        return Set.copyOf(candidate);
    }

    public boolean grantsScope(String scope) {
        return grantedScopes.contains(scope);
    }

    public ClientResourceAuthorizationId id() {
        return id;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public OAuthClientId oauthClientId() {
        return oauthClientId;
    }

    public ResourceId resourceId() {
        return resourceId;
    }

    public Set<String> grantedScopes() {
        return Set.copyOf(grantedScopes);
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientResourceAuthorization that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
