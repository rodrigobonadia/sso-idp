package com.ssoplatform.idp.domain.tenant;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link Tenant}. */
public final class TenantId {

    private final UUID value;

    private TenantId(UUID value) {
        this.value = value;
    }

    public static TenantId generate() {
        return new TenantId(UUID.randomUUID());
    }

    public static TenantId of(UUID value) {
        Objects.requireNonNull(value, "TenantId value must not be null");
        return new TenantId(value);
    }

    public static TenantId of(String value) {
        Objects.requireNonNull(value, "TenantId value must not be null");
        return new TenantId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantId tenantId)) return false;
        return value.equals(tenantId.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
