package com.ssoplatform.idp.domain.resource;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link Resource} (the internal database identity, not the
 * OAuth-facing {@link ResourceIdentifier}/audience that appears in requests). */
public final class ResourceId {

    private final UUID value;

    private ResourceId(UUID value) {
        this.value = value;
    }

    public static ResourceId generate() {
        return new ResourceId(UUID.randomUUID());
    }

    public static ResourceId of(UUID value) {
        Objects.requireNonNull(value, "ResourceId value must not be null");
        return new ResourceId(value);
    }

    public static ResourceId of(String value) {
        Objects.requireNonNull(value, "ResourceId value must not be null");
        return new ResourceId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ResourceId that)) return false;
        return value.equals(that.value);
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
