package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class AesGcmTotpSecretEncryptorAdapterTest {

    private final AesGcmTotpSecretEncryptorAdapter adapter =
            new AesGcmTotpSecretEncryptorAdapter("a-sufficiently-strong-test-secret");

    @Test
    void encryptThenDecryptRoundTripsTheOriginalSecretBytes() {
        byte[] original = "not-really-a-totp-secret-just-test-bytes".getBytes(StandardCharsets.UTF_8);

        EncryptedTotpSecret encrypted = adapter.encrypt(original);
        byte[] decrypted = adapter.decrypt(encrypted);

        assertThat(decrypted).isEqualTo(original);
    }

    @Test
    void encryptingTheSameBytesTwiceProducesDifferentCiphertextEachTime() {
        byte[] original = "same-input-every-time".getBytes(StandardCharsets.UTF_8);

        EncryptedTotpSecret first = adapter.encrypt(original);
        EncryptedTotpSecret second = adapter.encrypt(original);

        assertThat(first.value()).isNotEqualTo(second.value());
        assertThat(adapter.decrypt(first)).isEqualTo(original);
        assertThat(adapter.decrypt(second)).isEqualTo(original);
    }

    @Test
    void decryptingWithADifferentSecretFails() {
        byte[] original = "top-secret-totp-seed".getBytes(StandardCharsets.UTF_8);
        EncryptedTotpSecret encrypted = adapter.encrypt(original);

        AesGcmTotpSecretEncryptorAdapter differentAdapter = new AesGcmTotpSecretEncryptorAdapter("a-different-secret");

        assertThatThrownBy(() -> differentAdapter.decrypt(encrypted)).isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsABlankEncryptionSecretAtConstructionTime(String invalid) {
        assertThatThrownBy(() -> new AesGcmTotpSecretEncryptorAdapter(invalid)).isInstanceOf(IllegalStateException.class);
    }
}
