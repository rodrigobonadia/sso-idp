package com.ssoplatform.idp.domain.resource;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * A registered API resource server (RFC 8707 "resource"/audience) that Client Credentials tokens
 * can be issued for, always scoped to exactly one {@link
 * com.ssoplatform.idp.domain.tenant.Tenant} - mirroring {@link
 * com.ssoplatform.idp.domain.oauth.OAuthClient}'s tenant scoping and provisioning model: resources
 * are provisioned by hand via SQL/seed data for now (no admin API/UI yet - see {@code
 * architecture_decisions.md}), the same deliberate simplicity trade-off already made for OAuth
 * clients.
 *
 * <p>{@link #scopes} is this resource's OWN scope catalog (e.g. {@code orders:read}, {@code
 * orders:write}) - unlike {@link com.ssoplatform.idp.domain.oauth.OAuthClient#allowedScopes},
 * which is checked against a single platform-wide {@code SUPPORTED_SCOPES} set, a resource defines
 * whatever scopes make sense for its own API, so no such global set exists here. Which of a
 * resource's scopes a given client may actually request is a separate concern, modeled by {@link
 * ClientResourceAuthorization}.
 */
public final class Resource {

    private final ResourceId id;
    private final TenantId tenantId;
    private final ResourceIdentifier identifier;
    private String name;
    private final Set<String> scopes;
    private ResourceStatus status;
    private final Instant createdAt;

    private Resource(
            ResourceId id,
            TenantId tenantId,
            ResourceIdentifier identifier,
            String name,
            Set<String> scopes,
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

    /** Registers a brand-new, active resource. */
    public static Resource register(TenantId tenantId, ResourceIdentifier identifier, String name, Set<String> scopes) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(identifier, "identifier must not be null");
        return new Resource(
                ResourceId.generate(),
                tenantId,
                identifier,
                validateName(name),
                validateScopes(scopes),
                ResourceStatus.ACTIVE,
                Instant.now());
    }

    /** Reconstitutes a resource that already exists (used by persistence adapters). */
    public static Resource reconstitute(
            ResourceId id,
            TenantId tenantId,
            ResourceIdentifier identifier,
            String name,
            Set<String> scopes,
            ResourceStatus status,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(identifier, "identifier must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new Resource(id, tenantId, identifier, validateName(name), validateScopes(scopes), status, createdAt);
    }

    private static String validateName(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new IllegalArgumentException("Resource name must not be blank");
        }
        return candidate.trim();
    }

    private static Set<String> validateScopes(Set<String> candidate) {
        Objects.requireNonNull(candidate, "scopes must not be null");
        if (candidate.isEmpty()) {
            throw new IllegalArgumentException("A resource must define at least one scope");
        }
        for (String scope : candidate) {
            if (scope == null || scope.isBlank()) {
                throw new IllegalArgumentException("A resource scope must not be blank");
            }
            if (scope.chars().anyMatch(Character::isWhitespace)) {
                throw new IllegalArgumentException("Resource scope '" + scope + "' must not contain whitespace");
            }
        }
        return Set.copyOf(candidate);
    }

    public void rename(String newName) {
        this.name = validateName(newName);
    }

    public void disable() {
        if (status == ResourceStatus.DISABLED) {
            throw new ResourceStateException("Resource '" + identifier + "' is already disabled");
        }
        this.status = ResourceStatus.DISABLED;
    }

    public void enable() {
        if (status != ResourceStatus.DISABLED) {
            throw new ResourceStateException("Resource '" + identifier + "' is not disabled");
        }
        this.status = ResourceStatus.ACTIVE;
    }

    public boolean isUsable() {
        return status == ResourceStatus.ACTIVE;
    }

    public boolean supportsScope(String scope) {
        return scopes.contains(scope);
    }

    public ResourceId id() {
        return id;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public ResourceIdentifier identifier() {
        return identifier;
    }

    public String name() {
        return name;
    }

    public Set<String> scopes() {
        return Set.copyOf(scopes);
    }

    public ResourceStatus status() {
        return status;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Resource that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
