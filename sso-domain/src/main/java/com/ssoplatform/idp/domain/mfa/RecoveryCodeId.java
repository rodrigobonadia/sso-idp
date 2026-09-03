package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link RecoveryCode}. Mirrors {@code SigningKeyId} exactly. */
public final class RecoveryCodeId {

    private final UUID value;

    private RecoveryCodeId(UUID value) {
        this.value = value;
    }

    public static RecoveryCodeId generate() {
        return new RecoveryCodeId(UUID.randomUUID());
    }

    public static RecoveryCodeId of(UUID value) {
        Objects.requireNonNull(value, "RecoveryCodeId value must not be null");
        return new RecoveryCodeId(value);
    }

    public static RecoveryCodeId of(String value) {
        Objects.requireNonNull(value, "RecoveryCodeId value must not be null");
        return new RecoveryCodeId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RecoveryCodeId that)) return false;
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
