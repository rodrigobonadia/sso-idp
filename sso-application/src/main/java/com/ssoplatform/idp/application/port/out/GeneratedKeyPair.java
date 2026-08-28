package com.ssoplatform.idp.application.port.out;

import java.util.Arrays;
import java.util.Objects;

/**
 * Carries a freshly generated RSA key pair across the {@link SigningKeyPairGenerator} output port,
 * as raw DER-encoded bytes ({@code publicKeyDer} is X.509 {@code SubjectPublicKeyInfo}, {@code
 * privateKeyDer} is PKCS#8) - i.e. exactly {@code KeyPair.getPublic().getEncoded()} and {@code
 * KeyPair.getPrivate().getEncoded()}.
 *
 * <p>This is a plain class rather than a record specifically so {@link #toString()} can be
 * overridden to redact {@link #privateKeyDer()} - the private key material is unencrypted at this
 * point (encryption happens next, via {@link PrivateKeyEncryptor}), so it must never appear in a
 * log line or exception message, even transiently.
 */
public final class GeneratedKeyPair {

    private final byte[] publicKeyDer;
    private final byte[] privateKeyDer;

    public GeneratedKeyPair(byte[] publicKeyDer, byte[] privateKeyDer) {
        this.publicKeyDer = Objects.requireNonNull(publicKeyDer, "publicKeyDer must not be null").clone();
        this.privateKeyDer = Objects.requireNonNull(privateKeyDer, "privateKeyDer must not be null").clone();
    }

    public byte[] publicKeyDer() {
        return publicKeyDer.clone();
    }

    public byte[] privateKeyDer() {
        return privateKeyDer.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof GeneratedKeyPair that)) return false;
        return Arrays.equals(publicKeyDer, that.publicKeyDer) && Arrays.equals(privateKeyDer, that.privateKeyDer);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(publicKeyDer);
        result = 31 * result + Arrays.hashCode(privateKeyDer);
        return result;
    }

    @Override
    public String toString() {
        return "GeneratedKeyPair[publicKeyDer=<" + publicKeyDer.length + " bytes>, privateKeyDer=REDACTED]";
    }
}
