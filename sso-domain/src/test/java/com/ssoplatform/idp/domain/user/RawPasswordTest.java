package com.ssoplatform.idp.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class RawPasswordTest {

    @Test
    void acceptsAPasswordThatMeetsThePolicy() {
        RawPassword password = RawPassword.of("Str0ng!Passw0rd");

        assertThat(password.value()).isEqualTo("Str0ng!Passw0rd");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                "Short1!", // too short
                "alllowercase1!", // no uppercase
                "ALLUPPERCASE1!", // no lowercase
                "NoDigitsHere!", // no digit
                "NoSpecialChar1" // no special character
            })
    void rejectsPasswordsThatViolateThePolicy(String weak) {
        assertThatThrownBy(() -> RawPassword.of(weak)).isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void toStringNeverExposesThePlaintextValue() {
        RawPassword password = RawPassword.of("Str0ng!Passw0rd");

        assertThat(password.toString()).doesNotContain("Str0ng!Passw0rd").isEqualTo("RawPassword[REDACTED]");
    }
}
