package com.ssoplatform.idp.domain.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class OAuthClientIdTest {

    @Test
    void generatesADistinctIdEachTime() {
        assertThat(OAuthClientId.generate()).isNotEqualTo(OAuthClientId.generate());
    }

    @Test
    void ofUuidWrapsTheGivenValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(OAuthClientId.of(uuid).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringParsesAValidUuid() {
        UUID uuid = UUID.randomUUID();
        assertThat(OAuthClientId.of(uuid.toString())).isEqualTo(OAuthClientId.of(uuid));
    }

    @Test
    void rejectsANullUuid() {
        assertThatThrownBy(() -> OAuthClientId.of((UUID) null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void equalityIsBasedOnValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(OAuthClientId.of(uuid)).isEqualTo(OAuthClientId.of(uuid));
        assertThat(OAuthClientId.of(uuid)).hasSameHashCodeAs(OAuthClientId.of(uuid));
    }
}
