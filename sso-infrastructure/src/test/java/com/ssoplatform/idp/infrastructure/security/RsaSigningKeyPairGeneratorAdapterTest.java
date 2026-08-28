package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.application.port.out.GeneratedKeyPair;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.Test;

class RsaSigningKeyPairGeneratorAdapterTest {

    private final RsaSigningKeyPairGeneratorAdapter generator = new RsaSigningKeyPairGeneratorAdapter();

    @Test
    void generatesA4096BitRsaKeyPair() throws Exception {
        GeneratedKeyPair keyPair = generator.generate();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey =
                (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.publicKeyDer()));
        RSAPrivateKey privateKey =
                (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.privateKeyDer()));

        assertThat(publicKey.getModulus().bitLength()).isEqualTo(4096);
        assertThat(privateKey.getModulus()).isEqualTo(publicKey.getModulus());
    }

    @Test
    void generatesADistinctKeyPairEachTime() {
        GeneratedKeyPair first = generator.generate();
        GeneratedKeyPair second = generator.generate();

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void toStringNeverRevealsThePrivateKeyMaterial() {
        GeneratedKeyPair keyPair = generator.generate();

        assertThat(keyPair.toString()).contains("REDACTED");
    }
}
