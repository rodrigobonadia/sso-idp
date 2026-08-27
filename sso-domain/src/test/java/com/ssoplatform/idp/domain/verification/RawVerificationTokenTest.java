package com.ssoplatform.idp.domain.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class RawVerificationTokenTest {

    @Test
    void generateProducesADistinctHighEntropyTokenEachTime() {
        RawVerificationToken first = RawVerificationToken.generate();
        RawVerificationToken second = RawVerificationToken.generate();

        assertThat(first).isNotEqualTo(second);
        assertThat(first.value()).hasSizeGreaterThanOrEqualTo(32);
    }

    @Test
    void generatedTokensRoundTripThroughOf() {
        RawVerificationToken generated = RawVerificationToken.generate();

        assertThat(RawVerificationToken.of(generated.value())).isEqualTo(generated);
    }

    @Test
    void rejectsBlankInput() {
        assertThatThrownBy(() -> RawVerificationToken.of(null)).isInstanceOf(InvalidVerificationTokenException.class);
        assertThatThrownBy(() -> RawVerificationToken.of(" ")).isInstanceOf(InvalidVerificationTokenException.class);
    }

    @Test
    void rejectsValuesWithDisallowedCharacters() {
        assertThatThrownBy(() -> RawVerificationToken.of("has spaces in it"))
                .isInstanceOf(InvalidVerificationTokenException.class);
        assertThatThrownBy(() -> RawVerificationToken.of("has/slashes+and=signs"))
                .isInstanceOf(InvalidVerificationTokenException.class);
    }

    @Test
    void rejectsValuesThatAreTooShort() {
        assertThatThrownBy(() -> RawVerificationToken.of("short"))
                .isInstanceOf(InvalidVerificationTokenException.class);
    }

    @Test
    void toStringIsRedacted() {
        assertThat(RawVerificationToken.generate().toString()).isEqualTo("RawVerificationToken[REDACTED]");
    }

    @Test
    void equalityIsBasedOnValue() {
        RawVerificationToken token = RawVerificationToken.generate();
        assertThat(RawVerificationToken.of(token.value())).isEqualTo(token);
        assertThat(RawVerificationToken.of(token.value())).hasSameHashCodeAs(token);
    }
}
