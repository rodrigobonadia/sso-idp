package com.ssoplatform.idp.domain.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class SigningKeyTest {

    private final TenantId tenantId = TenantId.generate();
    private final KeyId kid = KeyId.generate();
    private final PublicKeyMaterial publicKey = PublicKeyMaterial.of("cHVibGljLWtleQ==");
    private final EncryptedPrivateKeyMaterial encryptedPrivateKey =
            EncryptedPrivateKeyMaterial.of("ZW5jcnlwdGVkLXByaXZhdGUta2V5");

    @Test
    void generateProducesACurrentKeyWithTheGivenFields() {
        SigningKey key = SigningKey.generate(tenantId, kid, publicKey, encryptedPrivateKey);

        assertThat(key.id()).isNotNull();
        assertThat(key.tenantId()).isEqualTo(tenantId);
        assertThat(key.kid()).isEqualTo(kid);
        assertThat(key.algorithm()).isEqualTo(SigningKey.ALGORITHM);
        assertThat(key.publicKey()).isEqualTo(publicKey);
        assertThat(key.encryptedPrivateKey()).isEqualTo(encryptedPrivateKey);
        assertThat(key.status()).isEqualTo(SigningKeyStatus.CURRENT);
        assertThat(key.isCurrent()).isTrue();
        assertThat(key.createdAt()).isNotNull();
    }

    @Test
    void generateRejectsNullArguments() {
        assertThatThrownBy(() -> SigningKey.generate(null, kid, publicKey, encryptedPrivateKey))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> SigningKey.generate(tenantId, null, publicKey, encryptedPrivateKey))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> SigningKey.generate(tenantId, kid, null, encryptedPrivateKey))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> SigningKey.generate(tenantId, kid, publicKey, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void retireTransitionsFromCurrentToRetired() {
        SigningKey key = SigningKey.generate(tenantId, kid, publicKey, encryptedPrivateKey);

        key.retire();

        assertThat(key.status()).isEqualTo(SigningKeyStatus.RETIRED);
        assertThat(key.isCurrent()).isFalse();
    }

    @Test
    void retiringAnAlreadyRetiredKeyThrows() {
        SigningKey key = SigningKey.generate(tenantId, kid, publicKey, encryptedPrivateKey);
        key.retire();

        assertThatThrownBy(key::retire).isInstanceOf(SigningKeyStateException.class);
    }

    @Test
    void reconstituteRestoresAllFieldsIncludingStatus() {
        SigningKeyId id = SigningKeyId.generate();
        Instant createdAt = Instant.now().minusSeconds(3600);

        SigningKey key = SigningKey.reconstitute(
                id, tenantId, kid, SigningKey.ALGORITHM, publicKey, encryptedPrivateKey, SigningKeyStatus.RETIRED, createdAt);

        assertThat(key.id()).isEqualTo(id);
        assertThat(key.tenantId()).isEqualTo(tenantId);
        assertThat(key.kid()).isEqualTo(kid);
        assertThat(key.algorithm()).isEqualTo(SigningKey.ALGORITHM);
        assertThat(key.publicKey()).isEqualTo(publicKey);
        assertThat(key.encryptedPrivateKey()).isEqualTo(encryptedPrivateKey);
        assertThat(key.status()).isEqualTo(SigningKeyStatus.RETIRED);
        assertThat(key.createdAt()).isEqualTo(createdAt);
    }

    @Test
    void reconstituteRejectsABlankAlgorithm() {
        assertThatThrownBy(() -> SigningKey.reconstitute(
                        SigningKeyId.generate(),
                        tenantId,
                        kid,
                        "  ",
                        publicKey,
                        encryptedPrivateKey,
                        SigningKeyStatus.CURRENT,
                        Instant.now()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equalityIsBasedOnId() {
        SigningKey key1 = SigningKey.generate(tenantId, kid, publicKey, encryptedPrivateKey);
        SigningKey key2 = SigningKey.reconstitute(
                key1.id(),
                tenantId,
                kid,
                SigningKey.ALGORITHM,
                publicKey,
                encryptedPrivateKey,
                SigningKeyStatus.CURRENT,
                key1.createdAt());

        assertThat(key1).isEqualTo(key2);
        assertThat(key1).hasSameHashCodeAs(key2);
    }
}
