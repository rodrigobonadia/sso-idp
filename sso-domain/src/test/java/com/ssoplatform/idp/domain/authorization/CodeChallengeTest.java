package com.ssoplatform.idp.domain.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class CodeChallengeTest {

    /** A real base64url, unpadded SHA-256 digest is always exactly 43 characters. */
    private static final String VALID_S256_SHAPED = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Test
    void acceptsAValidS256ShapedChallenge() {
        assertThat(CodeChallenge.of(VALID_S256_SHAPED).value()).isEqualTo(VALID_S256_SHAPED);
    }

    @Test
    void acceptsTheLongestAllowedLength() {
        String longest = "a".repeat(128);
        assertThat(CodeChallenge.of(longest).value()).isEqualTo(longest);
    }

    @Test
    void rejectsBlank() {
        assertThatThrownBy(() -> CodeChallenge.of(" ")).isInstanceOf(InvalidCodeChallengeException.class);
        assertThatThrownBy(() -> CodeChallenge.of(null)).isInstanceOf(InvalidCodeChallengeException.class);
    }

    @Test
    void rejectsTooShort() {
        assertThatThrownBy(() -> CodeChallenge.of("a".repeat(42)))
                .isInstanceOf(InvalidCodeChallengeException.class);
    }

    @Test
    void rejectsTooLong() {
        assertThatThrownBy(() -> CodeChallenge.of("a".repeat(129)))
                .isInstanceOf(InvalidCodeChallengeException.class);
    }

    @Test
    void rejectsDisallowedCharacters() {
        assertThatThrownBy(() -> CodeChallenge.of("a".repeat(42) + "+"))
                .isInstanceOf(InvalidCodeChallengeException.class);
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(CodeChallenge.of(VALID_S256_SHAPED)).isEqualTo(CodeChallenge.of(VALID_S256_SHAPED));
        assertThat(CodeChallenge.of(VALID_S256_SHAPED)).hasSameHashCodeAs(CodeChallenge.of(VALID_S256_SHAPED));
    }
}
