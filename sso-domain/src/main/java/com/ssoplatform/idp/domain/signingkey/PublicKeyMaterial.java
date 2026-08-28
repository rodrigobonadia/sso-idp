package com.ssoplatform.idp.domain.signingkey;

import java.util.Objects;

/**
 * Value object wrapping a signing key's public half, encoded as a Base64 string of its X.509
 * {@code SubjectPublicKeyInfo} DER representation (i.e. {@code PublicKey.getEncoded()}, Base64
 * encoded). This is exactly what {@code java.security.KeyFactory} needs to reconstruct a {@code
 * java.security.PublicKey} from - see the JWKS endpoint, which decodes this value back into an
 * {@code RSAPublicKey} to extract the modulus/exponent for the JWK's {@code n}/{@code e} fields.
 *
 * <p>Public keys are not secret by definition, so - unlike {@link EncryptedPrivateKeyMaterial} -
 * this type's {@code toString()} is not redacted.
 */
public final class PublicKeyMaterial {

    private final String value;

    private PublicKeyMaterial(String value) {
        this.value = value;
    }

    public static PublicKeyMaterial of(String base64EncodedDer) {
        if (base64EncodedDer == null || base64EncodedDer.isBlank()) {
            throw new InvalidPublicKeyMaterialException("Public key material must not be blank");
        }
        return new PublicKeyMaterial(base64EncodedDer);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PublicKeyMaterial that)) return false;
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
