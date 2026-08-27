package com.ssoplatform.idp.domain.user;

import java.util.Objects;

/**
 * Value object wrapping an already-hashed password.
 *
 * <p>The domain deliberately does not know which hashing algorithm produced this value
 * (BCrypt, Argon2, ...) - that decision belongs to the infrastructure layer's
 * implementation of the {@code PasswordHasher} port. The domain only guarantees that a
 * {@code HashedPassword} is never blank and is never confused with a {@link RawPassword}.
 */
public final class HashedPassword {

    private final String value;

    private HashedPassword(String value) {
        this.value = value;
    }

    public static HashedPassword of(String hash) {
        if (hash == null || hash.isBlank()) {
            throw new InvalidPasswordHashException("Password hash must not be blank");
        }
        return new HashedPassword(hash);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof HashedPassword that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "HashedPassword[REDACTED]";
    }
}
