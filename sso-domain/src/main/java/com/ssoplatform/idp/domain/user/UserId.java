package com.ssoplatform.idp.domain.user;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link User}. */
public final class UserId {

    private final UUID value;

    private UserId(UUID value) {
        this.value = value;
    }

    public static UserId generate() {
        return new UserId(UUID.randomUUID());
    }

    public static UserId of(UUID value) {
        Objects.requireNonNull(value, "UserId value must not be null");
        return new UserId(value);
    }

    public static UserId of(String value) {
        Objects.requireNonNull(value, "UserId value must not be null");
        return new UserId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserId userId)) return false;
        return value.equals(userId.value);
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
