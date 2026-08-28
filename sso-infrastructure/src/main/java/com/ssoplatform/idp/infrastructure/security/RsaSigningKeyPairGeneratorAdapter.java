package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.GeneratedKeyPair;
import com.ssoplatform.idp.application.port.out.SigningKeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link SigningKeyPairGenerator} output port with {@code java.security}'s own RSA
 * key pair generation - 4096 bits, per {@code architecture_decisions.md}. Every call produces a
 * brand-new, independent key pair; nothing here is deterministic or seeded.
 */
@Component
public class RsaSigningKeyPairGeneratorAdapter implements SigningKeyPairGenerator {

    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE_BITS = 4096;

    @Override
    public GeneratedKeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
            generator.initialize(KEY_SIZE_BITS);
            KeyPair keyPair = generator.generateKeyPair();
            return new GeneratedKeyPair(keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded());
        } catch (NoSuchAlgorithmException e) {
            // RSA is guaranteed to be available on every conforming JVM (JLS platform
            // requirement), so this can only ever indicate a broken JVM installation.
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
