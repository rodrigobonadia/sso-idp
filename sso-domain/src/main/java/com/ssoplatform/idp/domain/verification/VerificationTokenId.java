package com.ssoplatform.idp.domain.verification;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link EmailVerificationToken}. */
public final class VerificationTokenId {

    private final UUID value;

    private VerificationTokenId(UUID value) {
        this.value = value;
    }

    public static VerificationTokenId generate() {
        return new VerificationTokenId(UUID.randomUUID());
    }

    public static VerificationTokenId of(UUID value) {
        Objects.requireNonNull(value, "VerificationTokenId value must not be null");
        return new VerificationTokenId(value);
    }

    public static VerificationTokenId of(String value) {
        Objects.requireNonNull(value, "VerificationTokenId value must not be null");
        return new VerificationTokenId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof VerificationTokenId that)) return false;
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
