package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class AesGcmPrivateKeyEncryptorAdapterTest {

    private final AesGcmPrivateKeyEncryptorAdapter adapter =
            new AesGcmPrivateKeyEncryptorAdapter("a-sufficiently-strong-test-secret");

    @Test
    void encryptThenDecryptRoundTripsTheOriginalPrivateKeyBytes() {
        byte[] original = "not-really-a-private-key-just-test-bytes".getBytes(StandardCharsets.UTF_8);

        EncryptedPrivateKeyMaterial encrypted = adapter.encrypt(original);
        byte[] decrypted = adapter.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(original);
    }

    @Test
    void encryptingTheSameBytesTwiceProducesDifferentCiphertextEachTime() {
        byte[] original = "same-input-every-time".getBytes(StandardCharsets.UTF_8);

        EncryptedPrivateKeyMaterial first = adapter.encrypt(original);
        EncryptedPrivateKeyMaterial second = adapter.encrypt(original);

        // A fresh random IV per call means the stored value differs even for identical input.
        assertThat(first.value()).isNotEqualTo(second.value());
        assertThat(adapter.decrypt(first)).isEqualTo(original);
        assertThat(adapter.decrypt(second)).isEqualTo(original);
    }

    @Test
    void decryptingWithADifferentSecretFails() {
        byte[] original = "top-secret-key-bytes".getBytes(StandardCharsets.UTF_8);
        EncryptedPrivateKeyMaterial encrypted = adapter.encrypt(original);

        AesGcmPrivateKeyEncryptorAdapter differentAdapter = new AesGcmPrivateKeyEncryptorAdapter("a-different-secret");

        assertThatThrownBy(() -> differentAdapter.decrypt(encrypted)).isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsABlankEncryptionSecretAtConstructionTime(String invalid) {
        assertThatThrownBy(() -> new AesGcmPrivateKeyEncryptorAdapter(invalid))
                .isInstanceOf(IllegalStateException.class);
    }
}
