package com.ssoplatform.idp.domain.refreshtoken;

import java.util.Objects;
import java.util.UUID;

/**
 * Identity of a refresh token ROTATION CHAIN, shared by every {@link RefreshToken} descended from
 * the same original {@code authorization_code} redemption. A family is created once, when the
 * first refresh token in the chain is issued ({@link RefreshToken#issueFirst}), and every
 * subsequent rotation ({@link RefreshToken#continueFamily}) carries the same {@link
 * RefreshTokenFamilyId} forward unchanged - it is what lets reuse detection revoke every token
 * ever issued in that chain in one sweep (see {@code TokenUseCase}), and what the fixed 30-day
 * family expiry ({@link RefreshToken#familyExpiresAt()}) is scoped to, rather than to any single
 * token row.
 */
public final class RefreshTokenFamilyId {

    private final UUID value;

    private RefreshTokenFamilyId(UUID value) {
        this.value = value;
    }

    public static RefreshTokenFamilyId generate() {
        return new RefreshTokenFamilyId(UUID.randomUUID());
    }

    public static RefreshTokenFamilyId of(UUID value) {
        Objects.requireNonNull(value, "RefreshTokenFamilyId value must not be null");
        return new RefreshTokenFamilyId(value);
    }

    public static RefreshTokenFamilyId of(String value) {
        Objects.requireNonNull(value, "RefreshTokenFamilyId value must not be null");
        return new RefreshTokenFamilyId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshTokenFamilyId that)) return false;
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
