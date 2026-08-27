package com.ssoplatform.idp.domain.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class VerificationTokenIdTest {

    @Test
    void generatesADistinctIdEachTime() {
        assertThat(VerificationTokenId.generate()).isNotEqualTo(VerificationTokenId.generate());
    }

    @Test
    void ofUuidWrapsTheGivenValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(VerificationTokenId.of(uuid).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringParsesAValidUuid() {
        UUID uuid = UUID.randomUUID();
        assertThat(VerificationTokenId.of(uuid.toString())).isEqualTo(VerificationTokenId.of(uuid));
    }

    @Test
    void rejectsANullUuid() {
        assertThatThrownBy(() -> VerificationTokenId.of((UUID) null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void equalityIsBasedOnValue() {
        UUID uuid = UUID.randomUUID();
        assertThat(VerificationTokenId.of(uuid)).isEqualTo(VerificationTokenId.of(uuid));
        assertThat(VerificationTokenId.of(uuid)).hasSameHashCodeAs(VerificationTokenId.of(uuid));
    }
}
