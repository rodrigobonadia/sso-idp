package com.ssoplatform.idp.domain.passwordreset;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link PasswordResetToken}. */
public final class PasswordResetTokenId {

    private final UUID value;

    private PasswordResetTokenId(UUID value) {
        this.value = value;
    }

    public static PasswordResetTokenId generate() {
        return new PasswordResetTokenId(UUID.randomUUID());
    }

    public static PasswordResetTokenId of(UUID value) {
        Objects.requireNonNull(value, "PasswordResetTokenId value must not be null");
        return new PasswordResetTokenId(value);
    }

    public static PasswordResetTokenId of(String value) {
        Objects.requireNonNull(value, "PasswordResetTokenId value must not be null");
        return new PasswordResetTokenId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PasswordResetTokenId that)) return false;
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
