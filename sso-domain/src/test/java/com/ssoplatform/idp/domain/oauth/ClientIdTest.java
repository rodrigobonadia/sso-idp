package com.ssoplatform.idp.domain.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class ClientIdTest {

    @Test
    void wrapsAValidClientId() {
        assertThat(ClientId.of("acme-test-app").value()).isEqualTo("acme-test-app");
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertThat(ClientId.of("  acme-app  ").value()).isEqualTo("acme-app");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                " ",
                "ab", // too short: pattern requires at least 3 characters
                "has spaces",
                "has.dot",
                "-starts-with-hyphen"
            })
    void rejectsInvalidClientIds(String invalid) {
        assertThatThrownBy(() -> ClientId.of(invalid)).isInstanceOf(InvalidClientIdException.class);
    }

    @Test
    void rejectsClientIdsLongerThanOneHundredTwentyEightCharacters() {
        String tooLong = "a".repeat(129);

        assertThatThrownBy(() -> ClientId.of(tooLong)).isInstanceOf(InvalidClientIdException.class);
    }

    @Test
    void twoEqualClientIdsAreEqual() {
        assertThat(ClientId.of("acme-app")).isEqualTo(ClientId.of("acme-app"));
        assertThat(ClientId.of("acme-app")).hasSameHashCodeAs(ClientId.of("acme-app"));
    }
}
