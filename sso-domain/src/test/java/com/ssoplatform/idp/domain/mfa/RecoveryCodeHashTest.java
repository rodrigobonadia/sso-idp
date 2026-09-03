package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class RecoveryCodeHashTest {

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> RecoveryCodeHash.of(invalid)).isInstanceOf(InvalidRecoveryCodeHashException.class);
    }

    @Test
    void wrapsAValidValue() {
        assertThat(RecoveryCodeHash.of("$2a$12$somehash").value()).isEqualTo("$2a$12$somehash");
    }

    @Test
    void toStringNeverRevealsTheValue() {
        assertThat(RecoveryCodeHash.of("$2a$12$somehash").toString()).doesNotContain("$2a$12$somehash");
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(RecoveryCodeHash.of("$2a$12$somehash")).isEqualTo(RecoveryCodeHash.of("$2a$12$somehash"));
        assertThat(RecoveryCodeHash.of("$2a$12$somehash")).hasSameHashCodeAs(RecoveryCodeHash.of("$2a$12$somehash"));
    }
}
