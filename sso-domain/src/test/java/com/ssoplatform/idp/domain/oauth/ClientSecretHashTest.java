package com.ssoplatform.idp.domain.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class ClientSecretHashTest {

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> ClientSecretHash.of(invalid)).isInstanceOf(InvalidClientSecretHashException.class);
    }

    @Test
    void wrapsAValidHash() {
        assertThat(ClientSecretHash.of("abc123").value()).isEqualTo("abc123");
    }

    @Test
    void toStringNeverRevealsTheValue() {
        assertThat(ClientSecretHash.of("abc123").toString()).doesNotContain("abc123");
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(ClientSecretHash.of("abc123")).isEqualTo(ClientSecretHash.of("abc123"));
        assertThat(ClientSecretHash.of("abc123")).hasSameHashCodeAs(ClientSecretHash.of("abc123"));
    }
}
