package com.ssoplatform.idp.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class EmailTest {

    @Test
    void normalizesCasingAndWhitespace() {
        Email email = Email.of("  User@Example.COM  ");

        assertThat(email.value()).isEqualTo("user@example.com");
    }

    @Test
    void twoEmailsWithDifferentCasingAreEqual() {
        assertThat(Email.of("Someone@Example.com")).isEqualTo(Email.of("someone@example.com"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "not-an-email", "missing-domain@", "@missing-local.com", "double@@at.com"})
    void rejectsInvalidAddresses(String invalid) {
        assertThatThrownBy(() -> Email.of(invalid)).isInstanceOf(InvalidEmailException.class);
    }

    @Test
    void toStringReturnsTheNormalizedValue() {
        assertThat(Email.of("someone@example.com")).hasToString("someone@example.com");
    }
}
