package com.ssoplatform.idp.domain.devicecode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class UserCodeTest {

    @Test
    void generatesAnEightCharacterCodeFromTheRestrictedAlphabet() {
        UserCode code = UserCode.generate();

        assertThat(code.value()).hasSize(8);
        assertThat(code.value()).matches("^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{8}$");
    }

    @Test
    void formattedInsertsADashInTheMiddle() {
        UserCode code = UserCode.of("WDJPMX9K");

        assertThat(code.formatted()).isEqualTo("WDJP-MX9K");
    }

    @Test
    void ofAcceptsTheFormattedValueWithADash() {
        UserCode code = UserCode.of("WDJP-MX9K");

        assertThat(code.value()).isEqualTo("WDJPMX9K");
        assertThat(code.formatted()).isEqualTo("WDJP-MX9K");
    }

    @Test
    void ofNormalizesLowercaseAndExtraWhitespace() {
        UserCode code = UserCode.of(" wdjp mx9k ");

        assertThat(code.value()).isEqualTo("WDJPMX9K");
    }

    @Test
    void ofRejectsBlankInput() {
        assertThatThrownBy(() -> UserCode.of(""))
                .isInstanceOf(InvalidUserCodeException.class);
        assertThatThrownBy(() -> UserCode.of((String) null))
                .isInstanceOf(InvalidUserCodeException.class);
    }

    @Test
    void ofRejectsTheWrongLength() {
        assertThatThrownBy(() -> UserCode.of("WDJP-MX9"))
                .isInstanceOf(InvalidUserCodeException.class);
        assertThatThrownBy(() -> UserCode.of("WDJP-MX9KA"))
                .isInstanceOf(InvalidUserCodeException.class);
    }

    @Test
    void ofRejectsAmbiguousCharactersExcludedFromTheAlphabet() {
        assertThatThrownBy(() -> UserCode.of("WDJP-MX0K"))
                .isInstanceOf(InvalidUserCodeException.class);
        assertThatThrownBy(() -> UserCode.of("WDJP-MXOK"))
                .isInstanceOf(InvalidUserCodeException.class);
        assertThatThrownBy(() -> UserCode.of("WDJP-MX1K"))
                .isInstanceOf(InvalidUserCodeException.class);
        assertThatThrownBy(() -> UserCode.of("WDJP-MXIK"))
                .isInstanceOf(InvalidUserCodeException.class);
        assertThatThrownBy(() -> UserCode.of("WDJP-MXLK"))
                .isInstanceOf(InvalidUserCodeException.class);
    }

    @Test
    void equalsAndHashCodeAreValueBased() {
        UserCode a = UserCode.of("WDJP-MX9K");
        UserCode b = UserCode.of("wdjpmx9k");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }
}
