package com.ssoplatform.idp.domain.oauth;

import java.util.Objects;

/**
 * Value object wrapping an already-hashed OAuth client secret.
 *
 * <p>Mirrors {@code HashedPassword} in {@code domain.user}: the domain deliberately does not know
 * which hashing algorithm produced this value - that decision belongs to the infrastructure
 * layer's {@code ClientSecretHasher} implementation. This type only guarantees the value is never
 * blank and is never confused with a raw secret, a user's password hash, or a {@code TokenHash}.
 */
public final class ClientSecretHash {

    private final String value;

    private ClientSecretHash(String value) {
        this.value = value;
    }

    public static ClientSecretHash of(String hash) {
        if (hash == null || hash.isBlank()) {
            throw new InvalidClientSecretHashException("Client secret hash must not be blank");
        }
        return new ClientSecretHash(hash);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientSecretHash that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "ClientSecretHash[REDACTED]";
    }
}
