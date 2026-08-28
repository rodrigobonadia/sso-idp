package com.ssoplatform.idp.domain.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class PublicKeyMaterialTest {

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankValues(String invalid) {
        assertThatThrownBy(() -> PublicKeyMaterial.of(invalid)).isInstanceOf(InvalidPublicKeyMaterialException.class);
    }

    @Test
    void wrapsAValidValue() {
        assertThat(PublicKeyMaterial.of("YWJj").value()).isEqualTo("YWJj");
    }

    @Test
    void toStringIsNotRedactedSincePublicKeysAreNotSecret() {
        assertThat(PublicKeyMaterial.of("YWJj").toString()).isEqualTo("YWJj");
    }

    @Test
    void equalityIsBasedOnValue() {
        assertThat(PublicKeyMaterial.of("YWJj")).isEqualTo(PublicKeyMaterial.of("YWJj"));
        assertThat(PublicKeyMaterial.of("YWJj")).hasSameHashCodeAs(PublicKeyMaterial.of("YWJj"));
    }
}
