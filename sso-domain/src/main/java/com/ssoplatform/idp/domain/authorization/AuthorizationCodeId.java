package com.ssoplatform.idp.domain.authorization;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link AuthorizationCode}. */
public final class AuthorizationCodeId {

    private final UUID value;

    private AuthorizationCodeId(UUID value) {
        this.value = value;
    }

    public static AuthorizationCodeId generate() {
        return new AuthorizationCodeId(UUID.randomUUID());
    }

    public static AuthorizationCodeId of(UUID value) {
        Objects.requireNonNull(value, "AuthorizationCodeId value must not be null");
        return new AuthorizationCodeId(value);
    }

    public static AuthorizationCodeId of(String value) {
        Objects.requireNonNull(value, "AuthorizationCodeId value must not be null");
        return new AuthorizationCodeId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthorizationCodeId that)) return false;
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
