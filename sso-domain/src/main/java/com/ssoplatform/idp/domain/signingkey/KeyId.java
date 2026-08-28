package com.ssoplatform.idp.domain.signingkey;

import java.util.Objects;
import java.util.UUID;

/**
 * Value object for the JWT/JWKS-facing {@code kid} (key id) - the public identifier that appears
 * in a signed token's header and in the JWKS document, letting a verifier pick the right public
 * key among possibly several (a {@link SigningKeyStatus#CURRENT} one plus any {@link
 * SigningKeyStatus#RETIRED} ones still needed to verify tokens issued before a rotation).
 *
 * <p>Deliberately distinct from {@link SigningKeyId} (the internal database identity) the same way
 * {@code ClientId} is distinct from {@code OAuthClientId} - except a {@code kid}, unlike a {@code
 * client_id}, is always system-generated (never chosen by a human at provisioning time), so {@link
 * #generate()} is this type's only way to obtain a fresh value; {@link #of(String)} exists only
 * for reconstituting an already-persisted one.
 */
public final class KeyId {

    private final String value;

    private KeyId(String value) {
        this.value = value;
    }

    /** Generates a fresh, high-entropy key id. Never used to validate user input - a {@code kid}
     * is always produced by this method, never supplied externally. */
    public static KeyId generate() {
        return new KeyId(UUID.randomUUID().toString());
    }

    /** Reconstitutes a {@code kid} already generated and persisted. */
    public static KeyId of(String value) {
        if (value == null || value.isBlank()) {
            throw new InvalidKeyIdException("Key id must not be blank");
        }
        return new KeyId(value.trim());
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyId that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
