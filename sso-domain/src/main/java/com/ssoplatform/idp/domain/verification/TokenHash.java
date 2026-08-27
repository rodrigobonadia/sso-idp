package com.ssoplatform.idp.domain.verification;

import java.util.Objects;

/**
 * Wraps an opaque, already-hashed token value as persisted (e.g. a SHA-256 hex digest). Mirrors
 * {@code HashedPassword} in {@code domain.user}: this type never validates the hashing algorithm
 * or format beyond "not blank" - that choice belongs to whichever {@code VerificationTokenHasher}
 * adapter produced the value, not to this value object.
 */
public final class TokenHash {

    private final String value;

    private TokenHash(String value) {
        this.value = value;
    }

    public static TokenHash of(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new InvalidTokenHashException("Token hash must not be blank");
        }
        return new TokenHash(rawValue);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TokenHash that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "TokenHash[REDACTED]";
    }
}
