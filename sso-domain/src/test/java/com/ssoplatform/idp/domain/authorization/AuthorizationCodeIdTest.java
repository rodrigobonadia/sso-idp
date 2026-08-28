package com.ssoplatform.idp.domain.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuthorizationCodeIdTest {

    @Test
    void generateProducesDistinctIds() {
        assertThat(AuthorizationCodeId.generate()).isNotEqualTo(AuthorizationCodeId.generate());
    }

    @Test
    void ofUuidWrapsTheGivenValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(AuthorizationCodeId.of(uuid).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringParsesAValidUuid() {
        UUID uuid = UUID.randomUUID();
        assertThat(AuthorizationCodeId.of(uuid.toString()).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringRejectsAMalformedUuid() {
        assertThatThrownBy(() -> AuthorizationCodeId.of("not-a-uuid")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equalityIsBasedOnValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(AuthorizationCodeId.of(uuid)).isEqualTo(AuthorizationCodeId.of(uuid));
        assertThat(AuthorizationCodeId.of(uuid)).hasSameHashCodeAs(AuthorizationCodeId.of(uuid));
    }
}
