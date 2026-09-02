package com.ssoplatform.idp.domain.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class ResourceIdentifierTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://api.example.com/orders",
                "http://localhost:9000/orders-api",
                "urn:example:orders-api" // non-http(s) schemes are legitimate audience identifiers
            })
    void acceptsAbsoluteUris(String valid) {
        assertThat(ResourceIdentifier.of(valid).value()).isEqualTo(valid);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                " ",
                "/relative/path", // not absolute: no scheme
                "not a uri at all: ///",
                "https://api.example.com/orders#fragment" // fragments are rejected
            })
    void rejectsInvalidResourceIdentifiers(String invalid) {
        assertThatThrownBy(() -> ResourceIdentifier.of(invalid)).isInstanceOf(InvalidResourceIdentifierException.class);
    }

    @Test
    void twoEqualIdentifiersAreEqual() {
        assertThat(ResourceIdentifier.of("https://api.example.com/orders"))
                .isEqualTo(ResourceIdentifier.of("https://api.example.com/orders"));
    }
}
