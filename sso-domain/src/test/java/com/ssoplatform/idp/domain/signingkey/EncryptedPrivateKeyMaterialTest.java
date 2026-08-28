package com.ssoplatform.idp.domain.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class EncryptedPrivateKeyMaterialTest {

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> EncryptedPrivateKeyMaterial.of(invalid))
                .isInstanceOf(InvalidEncryptedPrivateKeyMaterialException.class);
    }

    @Test
    void wrapsAValidValue() {
        assertThat(EncryptedPrivateKeyMaterial.of("cGFzc3dvcmQ=").value()).isEqualTo("cGFzc3dvcmQ=");
    }

    @Test
    void toStringNeverRevealsTheValue() {
        assertThat(EncryptedPrivateKeyMaterial.of("cGFzc3dvcmQ=").toString()).doesNotContain("cGFzc3dvcmQ=");
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(EncryptedPrivateKeyMaterial.of("cGFzc3dvcmQ="))
                .isEqualTo(EncryptedPrivateKeyMaterial.of("cGFzc3dvcmQ="));
        assertThat(EncryptedPrivateKeyMaterial.of("cGFzc3dvcmQ="))
                .hasSameHashCodeAs(EncryptedPrivateKeyMaterial.of("cGFzc3dvcmQ="));
    }
}
