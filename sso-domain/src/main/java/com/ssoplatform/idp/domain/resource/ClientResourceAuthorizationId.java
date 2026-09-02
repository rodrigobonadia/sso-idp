package com.ssoplatform.idp.domain.resource;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link ClientResourceAuthorization}. */
public final class ClientResourceAuthorizationId {

    private final UUID value;

    private ClientResourceAuthorizationId(UUID value) {
        this.value = value;
    }

    public static ClientResourceAuthorizationId generate() {
        return new ClientResourceAuthorizationId(UUID.randomUUID());
    }

    public static ClientResourceAuthorizationId of(UUID value) {
        Objects.requireNonNull(value, "ClientResourceAuthorizationId value must not be null");
        return new ClientResourceAuthorizationId(value);
    }

    public static ClientResourceAuthorizationId of(String value) {
        Objects.requireNonNull(value, "ClientResourceAuthorizationId value must not be null");
        return new ClientResourceAuthorizationId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientResourceAuthorizationId that)) return false;
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
