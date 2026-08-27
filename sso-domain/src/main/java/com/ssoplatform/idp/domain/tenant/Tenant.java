package com.ssoplatform.idp.domain.tenant;

import java.time.Instant;
import java.util.Objects;

/**
 * A tenant is an isolated organization within the platform: it owns its own users and
 * OAuth clients, and is the unit of isolation for multi-tenancy (enforced at the
 * persistence layer via {@code tenant_id} + Row Level Security).
 *
 * <p>This class encapsulates every invariant about a tenant's lifecycle so that no other
 * layer can put a tenant into an inconsistent state (e.g. suspending it twice).
 */
public final class Tenant {

    private static final int MIN_NAME_LENGTH = 2;
    private static final int MAX_NAME_LENGTH = 150;

    private final TenantId id;
    private final TenantSlug slug;
    private String name;
    private TenantStatus status;
    private final Instant createdAt;

    private Tenant(TenantId id, TenantSlug slug, String name, TenantStatus status, Instant createdAt) {
        this.id = id;
        this.slug = slug;
        this.name = name;
        this.status = status;
        this.createdAt = createdAt;
    }

    /** Creates a brand-new, active tenant. */
    public static Tenant create(String name, TenantSlug slug) {
        Objects.requireNonNull(slug, "Tenant slug must not be null");
        return new Tenant(TenantId.generate(), slug, validateName(name), TenantStatus.ACTIVE, Instant.now());
    }

    /** Reconstitutes a tenant that already exists (used by persistence adapters). */
    public static Tenant reconstitute(
            TenantId id, TenantSlug slug, String name, TenantStatus status, Instant createdAt) {
        Objects.requireNonNull(id, "Tenant id must not be null");
        Objects.requireNonNull(slug, "Tenant slug must not be null");
        Objects.requireNonNull(status, "Tenant status must not be null");
        Objects.requireNonNull(createdAt, "Tenant createdAt must not be null");
        return new Tenant(id, slug, validateName(name), status, createdAt);
    }

    private static String validateName(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new InvalidTenantNameException("Tenant name must not be blank");
        }
        String trimmed = candidate.trim();
        if (trimmed.length() < MIN_NAME_LENGTH || trimmed.length() > MAX_NAME_LENGTH) {
            throw new InvalidTenantNameException(
                    "Tenant name must be between " + MIN_NAME_LENGTH + " and " + MAX_NAME_LENGTH + " characters");
        }
        return trimmed;
    }

    public void rename(String newName) {
        this.name = validateName(newName);
    }

    public void suspend() {
        if (status == TenantStatus.SUSPENDED) {
            throw new TenantStateException("Tenant '" + slug + "' is already suspended");
        }
        this.status = TenantStatus.SUSPENDED;
    }

    public void activate() {
        if (status == TenantStatus.ACTIVE) {
            throw new TenantStateException("Tenant '" + slug + "' is already active");
        }
        this.status = TenantStatus.ACTIVE;
    }

    public boolean isActive() {
        return status == TenantStatus.ACTIVE;
    }

    public TenantId id() {
        return id;
    }

    public TenantSlug slug() {
        return slug;
    }

    public String name() {
        return name;
    }

    public TenantStatus status() {
        return status;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Tenant tenant)) return false;
        return id.equals(tenant.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
