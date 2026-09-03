package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link EmailOtpCredential}. Mirrors {@link TotpCredentialId} exactly. */
public final class EmailOtpCredentialId {

    private final UUID value;

    private EmailOtpCredentialId(UUID value) {
        this.value = value;
    }

    public static EmailOtpCredentialId generate() {
        return new EmailOtpCredentialId(UUID.randomUUID());
    }

    public static EmailOtpCredentialId of(UUID value) {
        Objects.requireNonNull(value, "EmailOtpCredentialId value must not be null");
        return new EmailOtpCredentialId(value);
    }

    public static EmailOtpCredentialId of(String value) {
        Objects.requireNonNull(value, "EmailOtpCredentialId value must not be null");
        return new EmailOtpCredentialId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailOtpCredentialId that)) return false;
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
