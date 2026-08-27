package com.ssoplatform.idp.domain.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class PasswordResetTokenIdTest {

    @Test
    void generatesADistinctIdEachTime() {
        assertThat(PasswordResetTokenId.generate()).isNotEqualTo(PasswordResetTokenId.generate());
    }

    @Test
    void ofUuidWrapsTheGivenValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(PasswordResetTokenId.of(uuid).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringParsesAValidUuid() {
        UUID uuid = UUID.randomUUID();
        assertThat(PasswordResetTokenId.of(uuid.toString())).isEqualTo(PasswordResetTokenId.of(uuid));
    }

    @Test
    void rejectsANullUuid() {
        assertThatThrownBy(() -> PasswordResetTokenId.of((UUID) null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void equalityIsBasedOnValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(PasswordResetTokenId.of(uuid)).isEqualTo(PasswordResetTokenId.of(uuid));
        assertThat(PasswordResetTokenId.of(uuid)).hasSameHashCodeAs(PasswordResetTokenId.of(uuid));
    }
}
