package com.ssoplatform.idp.domain.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class KeyIdTest {

    @Test
    void generatesADistinctKeyIdEachTime() {
        assertThat(KeyId.generate()).isNotEqualTo(KeyId.generate());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void ofRejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> KeyId.of(invalid)).isInstanceOf(InvalidKeyIdException.class);
    }

    @Test
    void ofTrimsAndWrapsAValidValue() {
        assertThat(KeyId.of("  some-kid  ").value()).isEqualTo("some-kid");
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(KeyId.of("same-kid")).isEqualTo(KeyId.of("same-kid"));
        assertThat(KeyId.of("same-kid")).hasSameHashCodeAs(KeyId.of("same-kid"));
    }
}
