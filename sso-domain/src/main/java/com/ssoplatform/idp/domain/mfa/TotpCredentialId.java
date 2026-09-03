package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link TotpCredential}. Mirrors {@code SigningKeyId} exactly. */
public final class TotpCredentialId {

    private final UUID value;

    private TotpCredentialId(UUID value) {
        this.value = value;
    }

    public static TotpCredentialId generate() {
        return new TotpCredentialId(UUID.randomUUID());
    }

    public static TotpCredentialId of(UUID value) {
        Objects.requireNonNull(value, "TotpCredentialId value must not be null");
        return new TotpCredentialId(value);
    }

    public static TotpCredentialId of(String value) {
        Objects.requireNonNull(value, "TotpCredentialId value must not be null");
        return new TotpCredentialId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TotpCredentialId that)) return false;
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
