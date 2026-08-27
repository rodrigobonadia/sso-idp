package com.ssoplatform.idp.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class HashedPasswordTest {

    @Test
    void wrapsAnOpaqueHashValue() {
        HashedPassword hash = HashedPassword.of("$2a$10$somehashvalue");

        assertThat(hash.value()).isEqualTo("$2a$10$somehashvalue");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    void rejectsBlankHashes(String blank) {
        assertThatThrownBy(() -> HashedPassword.of(blank)).isInstanceOf(InvalidPasswordHashException.class);
    }

    @Test
    void toStringNeverExposesTheHash() {
        HashedPassword hash = HashedPassword.of("$2a$10$somehashvalue");

        assertThat(hash.toString()).doesNotContain("somehashvalue");
    }
}
