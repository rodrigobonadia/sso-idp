package com.ssoplatform.idp.domain.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class SigningKeyIdTest {

    @Test
    void generatesADistinctIdEachTime() {
        assertThat(SigningKeyId.generate()).isNotEqualTo(SigningKeyId.generate());
    }

    @Test
    void ofUuidWrapsTheGivenValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(SigningKeyId.of(uuid).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringParsesAValidUuid() {
        UUID uuid = UUID.randomUUID();
        assertThat(SigningKeyId.of(uuid.toString())).isEqualTo(SigningKeyId.of(uuid));
    }

    @Test
    void rejectsANullUuid() {
        assertThatThrownBy(() -> SigningKeyId.of((UUID) null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void equalityIsBasedOnValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(SigningKeyId.of(uuid)).isEqualTo(SigningKeyId.of(uuid));
        assertThat(SigningKeyId.of(uuid)).hasSameHashCodeAs(SigningKeyId.of(uuid));
    }
}
