package com.ssoplatform.idp.domain.refreshtoken;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for a single {@link RefreshToken} row - one per rotation, not one per family (see {@link RefreshTokenFamilyId}). */
public final class RefreshTokenId {

    private final UUID value;

    private RefreshTokenId(UUID value) {
        this.value = value;
    }

    public static RefreshTokenId generate() {
        return new RefreshTokenId(UUID.randomUUID());
    }

    public static RefreshTokenId of(UUID value) {
        Objects.requireNonNull(value, "RefreshTokenId value must not be null");
        return new RefreshTokenId(value);
    }

    public static RefreshTokenId of(String value) {
        Objects.requireNonNull(value, "RefreshTokenId value must not be null");
        return new RefreshTokenId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshTokenId that)) return false;
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
