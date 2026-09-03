package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;

/**
 * Value object wrapping a TOTP secret's encrypted-at-rest form - always already encrypted (AES-
 * 256-GCM, see {@code AesGcmTotpSecretEncryptorAdapter}) before it ever reaches the domain layer
 * or persistence. Mirrors {@code EncryptedPrivateKeyMaterial} exactly, including the redacted
 * {@link #toString()}: a stray log statement or exception message can never leak the secret that
 * seeds every future code a user's authenticator app will ever generate.
 */
public final class EncryptedTotpSecret {

    private final String value;

    private EncryptedTotpSecret(String value) {
        this.value = value;
    }

    public static EncryptedTotpSecret of(String base64EncodedCiphertext) {
        if (base64EncodedCiphertext == null || base64EncodedCiphertext.isBlank()) {
            throw new InvalidEncryptedTotpSecretException("Encrypted TOTP secret must not be blank");
        }
        return new EncryptedTotpSecret(base64EncodedCiphertext);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EncryptedTotpSecret that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "EncryptedTotpSecret[REDACTED]";
    }
}
