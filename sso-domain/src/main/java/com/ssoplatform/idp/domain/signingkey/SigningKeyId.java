package com.ssoplatform.idp.domain.signingkey;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link SigningKey} (the internal database identity, not the
 * JWT/JWKS-facing {@link KeyId}). Mirrors {@code OAuthClientId} exactly. */
public final class SigningKeyId {

    private final UUID value;

    private SigningKeyId(UUID value) {
        this.value = value;
    }

    public static SigningKeyId generate() {
        return new SigningKeyId(UUID.randomUUID());
    }

    public static SigningKeyId of(UUID value) {
        Objects.requireNonNull(value, "SigningKeyId value must not be null");
        return new SigningKeyId(value);
    }

    public static SigningKeyId of(String value) {
        Objects.requireNonNull(value, "SigningKeyId value must not be null");
        return new SigningKeyId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SigningKeyId that)) return false;
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
