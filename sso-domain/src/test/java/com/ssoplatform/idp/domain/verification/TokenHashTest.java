package com.ssoplatform.idp.domain.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class TokenHashTest {

    @Test
    void wrapsAGivenValue() {
        assertThat(TokenHash.of("abc123").value()).isEqualTo("abc123");
    }

    @Test
    void rejectsBlankValues() {
        assertThatThrownBy(() -> TokenHash.of(" ")).isInstanceOf(InvalidTokenHashException.class);
        assertThatThrownBy(() -> TokenHash.of(null)).isInstanceOf(InvalidTokenHashException.class);
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(TokenHash.of("abc123")).isEqualTo(TokenHash.of("abc123"));
        assertThat(TokenHash.of("abc123")).hasSameHashCodeAs(TokenHash.of("abc123"));
        assertThat(TokenHash.of("abc123")).isNotEqualTo(TokenHash.of("xyz789"));
    }

    @Test
    void toStringIsRedacted() {
        assertThat(TokenHash.of("super-secret-hash").toString()).isEqualTo("TokenHash[REDACTED]");
    }
}
