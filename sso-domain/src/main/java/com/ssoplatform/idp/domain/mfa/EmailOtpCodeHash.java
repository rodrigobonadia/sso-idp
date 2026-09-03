package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;

/**
 * Value object wrapping an already-hashed e-mail OTP code. Mirrors {@link RecoveryCodeHash}
 * exactly, and for the same reason: a 6-digit e-mail OTP code carries only ~20 bits of entropy -
 * even lower than a recovery code's ~50 - so it is hashed with the same slow, salted algorithm
 * (BCrypt, via {@code EmailOtpCodeHasher}) rather than {@code domain.verification.TokenHash}'s fast
 * unsalted SHA-256, which is only appropriate for high-entropy 256-bit values. Kept as its own type
 * (not reusing {@code RecoveryCodeHash}) purely for compile-time type safety: an e-mail OTP code
 * and a recovery code are different domain concepts with different formats and lifecycles, even
 * though both happen to be hashed the same way.
 */
public final class EmailOtpCodeHash {

    private final String value;

    private EmailOtpCodeHash(String value) {
        this.value = value;
    }

    public static EmailOtpCodeHash of(String hash) {
        if (hash == null || hash.isBlank()) {
            throw new InvalidEmailOtpCodeHashException("Email OTP code hash must not be blank");
        }
        return new EmailOtpCodeHash(hash);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailOtpCodeHash that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "EmailOtpCodeHash[REDACTED]";
    }
}
