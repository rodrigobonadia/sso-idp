package com.ssoplatform.idp.domain.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class TenantIdTest {

    @Test
    void generateProducesARandomId() {
        assertThat(TenantId.generate()).isNotEqualTo(TenantId.generate());
    }

    @Test
    void ofUuidWrapsTheGivenValue() {
        UUID uuid = UUID.randomUUID();

        assertThat(TenantId.of(uuid).value()).isEqualTo(uuid);
    }

    @Test
    void ofStringParsesAValidUuid() {
        UUID uuid = UUID.randomUUID();

        assertThat(TenantId.of(uuid.toString())).isEqualTo(TenantId.of(uuid));
    }

    @Test
    void ofRejectsNullUuid() {
        assertThatThrownBy(() -> TenantId.of((UUID) null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void toStringReturnsTheUuidRepresentation() {
        UUID uuid = UUID.randomUUID();

        assertThat(TenantId.of(uuid)).hasToString(uuid.toString());
    }
}
