package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class RawRecoveryCodeTest {

    private static final Pattern EXPECTED_SHAPE = Pattern.compile("^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$");

    @Test
    void generateProducesTheExpectedShape() {
        String value = RawRecoveryCode.generate().value();

        assertThat(value).matches(EXPECTED_SHAPE);
    }

    @Test
    void generateNeverProducesTheSameCodeTwice() {
        assertThat(RawRecoveryCode.generate().value()).isNotEqualTo(RawRecoveryCode.generate().value());
    }

    @Test
    void ofNormalizesCaseAndWhitespace() {
        RawRecoveryCode generated = RawRecoveryCode.generate();

        RawRecoveryCode parsed = RawRecoveryCode.of("  " + generated.value().toLowerCase(java.util.Locale.ROOT) + "  ");

        assertThat(parsed).isEqualTo(generated);
    }

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> RawRecoveryCode.of(invalid)).isInstanceOf(InvalidRecoveryCodeException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ABCDE", "ABCDE-FGH", "ABCDE-FGHIJK", "ABCDEFGHIJ", "ABCDI-FGHJK", "ABCDL-FGHJK"})
    void rejectsAnythingNotMatchingTheExpectedShape(String invalid) {
        assertThatThrownBy(() -> RawRecoveryCode.of(invalid)).isInstanceOf(InvalidRecoveryCodeException.class);
    }

    @Test
    void toStringNeverRevealsTheValue() {
        RawRecoveryCode code = RawRecoveryCode.generate();

        assertThat(code.toString()).doesNotContain(code.value());
    }
}
