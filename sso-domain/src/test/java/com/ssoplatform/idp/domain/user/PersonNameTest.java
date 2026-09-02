package com.ssoplatform.idp.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class PersonNameTest {

    @Test
    void trimsSurroundingWhitespaceButPreservesCasing() {
        PersonName name = PersonName.of("  Jean-Luc  ");

        assertThat(name.value()).isEqualTo("Jean-Luc");
    }

    @Test
    void twoNamesWithDifferentCasingAreNotEqual() {
        assertThat(PersonName.of("Anne")).isNotEqualTo(PersonName.of("anne"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    void rejectsBlankNames(String invalid) {
        assertThatThrownBy(() -> PersonName.of(invalid)).isInstanceOf(InvalidPersonNameException.class);
    }

    @Test
    void rejectsNamesLongerThanTheMaximumLength() {
        String tooLong = "a".repeat(101);

        assertThatThrownBy(() -> PersonName.of(tooLong)).isInstanceOf(InvalidPersonNameException.class);
    }

    @Test
    void acceptsANameAtExactlyTheMaximumLength() {
        String maxLength = "a".repeat(100);

        assertThat(PersonName.of(maxLength).value()).isEqualTo(maxLength);
    }

    @Test
    void toStringReturnsTheTrimmedValue() {
        assertThat(PersonName.of("  Doe  ")).hasToString("Doe");
    }
}
