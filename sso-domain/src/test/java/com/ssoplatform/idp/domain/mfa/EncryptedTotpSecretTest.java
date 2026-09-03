package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class EncryptedTotpSecretTest {

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> EncryptedTotpSecret.of(invalid))
                .isInstanceOf(InvalidEncryptedTotpSecretException.class);
    }

    @Test
    void wrapsAValidValue() {
        assertThat(EncryptedTotpSecret.of("Y2lwaGVydGV4dA==").value()).isEqualTo("Y2lwaGVydGV4dA==");
    }

    @Test
    void toStringNeverRevealsTheValue() {
        assertThat(EncryptedTotpSecret.of("Y2lwaGVydGV4dA==").toString()).doesNotContain("Y2lwaGVydGV4dA==");
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(EncryptedTotpSecret.of("Y2lwaGVydGV4dA==")).isEqualTo(EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="));
        assertThat(EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="))
                .hasSameHashCodeAs(EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="));
    }
}
