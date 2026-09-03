package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class RecoveryCodeTest {

    private final UserId userId = UserId.generate();
    private final RecoveryCodeHash codeHash = RecoveryCodeHash.of("$2a$12$somehash");

    @Test
    void issueProducesAnUnconsumedCode() {
        RecoveryCode code = RecoveryCode.issue(userId, codeHash, Instant.now());

        assertThat(code.id()).isNotNull();
        assertThat(code.userId()).isEqualTo(userId);
        assertThat(code.codeHash()).isEqualTo(codeHash);
        assertThat(code.isConsumed()).isFalse();
        assertThat(code.consumedAt()).isNull();
    }

    @Test
    void consumeMarksTheCodeAsUsed() {
        RecoveryCode code = RecoveryCode.issue(userId, codeHash, Instant.now());
        Instant consumedAt = Instant.now();

        code.consume(consumedAt);

        assertThat(code.isConsumed()).isTrue();
        assertThat(code.consumedAt()).isEqualTo(consumedAt);
    }

    @Test
    void consumingAnAlreadyConsumedCodeThrows() {
        RecoveryCode code = RecoveryCode.issue(userId, codeHash, Instant.now());
        code.consume(Instant.now());

        assertThatThrownBy(() -> code.consume(Instant.now()))
                .isInstanceOf(RecoveryCodeAlreadyConsumedException.class);
    }

    @Test
    void reconstituteRestoresAllFields() {
        RecoveryCodeId id = RecoveryCodeId.generate();
        Instant createdAt = Instant.now().minusSeconds(3600);
        Instant consumedAt = Instant.now().minusSeconds(60);

        RecoveryCode code = RecoveryCode.reconstitute(id, userId, codeHash, consumedAt, createdAt);

        assertThat(code.id()).isEqualTo(id);
        assertThat(code.userId()).isEqualTo(userId);
        assertThat(code.codeHash()).isEqualTo(codeHash);
        assertThat(code.consumedAt()).isEqualTo(consumedAt);
        assertThat(code.createdAt()).isEqualTo(createdAt);
    }

    @Test
    void equalityIsBasedOnId() {
        RecoveryCode code1 = RecoveryCode.issue(userId, codeHash, Instant.now());
        RecoveryCode code2 = RecoveryCode.reconstitute(code1.id(), userId, codeHash, null, code1.createdAt());

        assertThat(code1).isEqualTo(code2);
        assertThat(code1).hasSameHashCodeAs(code2);
    }
}
