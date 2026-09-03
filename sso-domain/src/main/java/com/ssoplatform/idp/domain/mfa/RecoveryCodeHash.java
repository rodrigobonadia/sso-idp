package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;

/**
 * Value object wrapping an already-hashed MFA recovery code. Mirrors {@code ClientSecretHash}: the
 * domain does not know which hashing algorithm produced this value - see {@code
 * RecoveryCodeHasher}.
 *
 * <p>Deliberately its own type rather than reusing {@code domain.verification.TokenHash}: a
 * recovery code (~50 bits of entropy, see {@link RawRecoveryCode}) is hashed with a slow, salted
 * algorithm (BCrypt, like a password) rather than {@code TokenHash}'s fast unsalted SHA-256 (which
 * is only appropriate for the 256-bit values {@code VerificationTokenHasher} deals with) - and a
 * salted hash cannot be looked up by re-hashing and comparing equality the way {@code TokenHash}
 * is, so keeping the types distinct prevents the two lookup strategies from ever being confused.
 */
public final class RecoveryCodeHash {

    private final String value;

    private RecoveryCodeHash(String value) {
        this.value = value;
    }

    public static RecoveryCodeHash of(String hash) {
        if (hash == null || hash.isBlank()) {
            throw new InvalidRecoveryCodeHashException("Recovery code hash must not be blank");
        }
        return new RecoveryCodeHash(hash);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RecoveryCodeHash that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "RecoveryCodeHash[REDACTED]";
    }
}
