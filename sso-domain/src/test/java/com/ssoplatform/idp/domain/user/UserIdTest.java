package com.ssoplatform.idp.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class UserIdTest {

    @Test
    void generateProducesARandomId() {
        assertThat(UserId.generate()).isNotEqualTo(UserId.generate());
    }

    @Test
    void ofUuidWrapsTheGivenValue() {
        UUID uuid = UUID.randomUUID();

        assertThat(UserId.of(uuid).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringParsesAValidUuid() {
        UUID uuid = UUID.randomUUID();

        assertThat(UserId.of(uuid.toString())).isEqualTo(UserId.of(uuid));
    }

    @Test
    void ofRejectsNullUuid() {
        assertThatThrownBy(() -> UserId.of((UUID) null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void toStringReturnsTheUuidRepresentation() {
        UUID uuid = UUID.randomUUID();

        assertThat(UserId.of(uuid)).hasToString(uuid.toString());
    }
}
