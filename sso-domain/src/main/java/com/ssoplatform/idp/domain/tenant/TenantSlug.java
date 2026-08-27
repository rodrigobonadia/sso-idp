package com.ssoplatform.idp.domain.tenant;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value object for the tenant's unique, URL-safe identifier
 * (e.g. used as a path segment or subdomain: {@code https://<slug>.ssoplatform.example}).
 */
public final class TenantSlug {

    private static final int MAX_LENGTH = 63;
    private static final Pattern PATTERN = Pattern.compile("^[a-z][a-z0-9-]{1,62}$");

    private final String value;

    private TenantSlug(String value) {
        this.value = value;
    }

    public static TenantSlug of(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new InvalidTenantSlugException("Tenant slug must not be blank");
        }
        String normalized = rawValue.trim().toLowerCase();
        if (normalized.length() > MAX_LENGTH) {
            throw new InvalidTenantSlugException("Tenant slug must not exceed " + MAX_LENGTH + " characters");
        }
        if (!PATTERN.matcher(normalized).matches()) {
            throw new InvalidTenantSlugException(
                    "Tenant slug '" + rawValue + "' must start with a letter and contain only "
                            + "lowercase letters, digits and hyphens");
        }
        return new TenantSlug(normalized);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantSlug that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
