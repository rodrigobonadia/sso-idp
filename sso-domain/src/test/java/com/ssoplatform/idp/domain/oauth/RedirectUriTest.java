package com.ssoplatform.idp.domain.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class RedirectUriTest {

    @ParameterizedTest
    @ValueSource(strings = {"https://app.example.com/callback", "http://localhost:4000/callback"})
    void acceptsAbsoluteHttpAndHttpsUris(String valid) {
        assertThat(RedirectUri.of(valid).value()).isEqualTo(valid);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                " ",
                "/relative/path", // not absolute: no scheme
                "not a uri at all: ///",
                "myapp://callback", // non-http(s) scheme: only confidential/server-side clients are modeled so far
                "https://app.example.com/callback#fragment" // fragments are rejected
            })
    void rejectsInvalidRedirectUris(String invalid) {
        assertThatThrownBy(() -> RedirectUri.of(invalid)).isInstanceOf(InvalidRedirectUriException.class);
    }

    @Test
    void twoEqualUrisAreEqual() {
        assertThat(RedirectUri.of("https://app.example.com/callback"))
                .isEqualTo(RedirectUri.of("https://app.example.com/callback"));
    }

    @Test
    void aSubPathOfARegisteredUriIsNotEqualToIt() {
        // Guards against open-redirect via prefix matching: see the class Javadoc on exact-match.
        assertThat(RedirectUri.of("https://app.example.com/callback"))
                .isNotEqualTo(RedirectUri.of("https://app.example.com/callback/evil"));
    }
}
