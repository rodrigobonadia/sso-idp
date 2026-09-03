package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link EmailOtpCode}. Mirrors {@link TotpCredentialId} exactly. */
public final class EmailOtpCodeId {

    private final UUID value;

    private EmailOtpCodeId(UUID value) {
        this.value = value;
    }

    public static EmailOtpCodeId generate() {
        return new EmailOtpCodeId(UUID.randomUUID());
    }

    public static EmailOtpCodeId of(UUID value) {
        Objects.requireNonNull(value, "EmailOtpCodeId value must not be null");
        return new EmailOtpCodeId(value);
    }

    public static EmailOtpCodeId of(String value) {
        Objects.requireNonNull(value, "EmailOtpCodeId value must not be null");
        return new EmailOtpCodeId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailOtpCodeId that)) return false;
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
