package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class TotpCodeTest {

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> TotpCode.of(invalid)).isInstanceOf(InvalidTotpCodeException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"12345", "1234567", "12345a", "12 345", "-12345"})
    void rejectsAnythingOtherThanExactlySixDigits(String invalid) {
        assertThatThrownBy(() -> TotpCode.of(invalid)).isInstanceOf(InvalidTotpCodeException.class);
    }

    @Test
    void acceptsExactlySixDigits() {
        assertThat(TotpCode.of("012345").value()).isEqualTo("012345");
    }

    @Test
    void toStringNeverRevealsTheValue() {
        assertThat(TotpCode.of("012345").toString()).doesNotContain("012345");
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(TotpCode.of("012345")).isEqualTo(TotpCode.of("012345"));
        assertThat(TotpCode.of("012345")).hasSameHashCodeAs(TotpCode.of("012345"));
    }
}
