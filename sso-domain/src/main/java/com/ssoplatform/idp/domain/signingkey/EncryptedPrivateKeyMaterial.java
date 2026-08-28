package com.ssoplatform.idp.domain.signingkey;

import java.util.Objects;

/**
 * Value object wrapping a signing key's private half - always already encrypted (AES-256-GCM, see
 * {@code AesGcmPrivateKeyEncryptorAdapter}) before it ever reaches the domain layer or persistence.
 * The domain never sees, and this type never carries, a plaintext private key.
 *
 * <p>Mirrors {@code ClientSecretHash}'s "opaque, redacted" shape: {@code toString()} never reveals
 * {@link #value()}, so a stray log statement or exception message can never leak key material,
 * even though - unlike a client secret hash - this value is reversible (by design, via {@code
 * PrivateKeyEncryptor#decrypt}) rather than one-way.
 */
public final class EncryptedPrivateKeyMaterial {

    private final String value;

    private EncryptedPrivateKeyMaterial(String value) {
        this.value = value;
    }

    public static EncryptedPrivateKeyMaterial of(String base64EncodedCiphertext) {
        if (base64EncodedCiphertext == null || base64EncodedCiphertext.isBlank()) {
            throw new InvalidEncryptedPrivateKeyMaterialException("Encrypted private key material must not be blank");
        }
        return new EncryptedPrivateKeyMaterial(base64EncodedCiphertext);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EncryptedPrivateKeyMaterial that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "EncryptedPrivateKeyMaterial[REDACTED]";
    }
}
