package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class MfaChallengeTest {

    private final UserId userId = UserId.generate();
    private final TenantId tenantId = TenantId.generate();
    private final TokenHash tokenHash = TokenHash.of("some-hash-value");

    @Test
    void issueProducesAnUnconsumedChallengeValidForTheGivenDuration() {
        Instant now = Instant.now();

        MfaChallenge challenge = MfaChallenge.issue(userId, tenantId, tokenHash, now, Duration.ofMinutes(5));

        assertThat(challenge.id()).isNotNull();
        assertThat(challenge.userId()).isEqualTo(userId);
        assertThat(challenge.tenantId()).isEqualTo(tenantId);
        assertThat(challenge.tokenHash()).isEqualTo(tokenHash);
        assertThat(challenge.expiresAt()).isEqualTo(now.plus(Duration.ofMinutes(5)));
        assertThat(challenge.isConsumed()).isFalse();
        assertThat(challenge.isExpired(now)).isFalse();
    }

    @Test
    void consumeMarksTheChallengeAsUsed() {
        MfaChallenge challenge =
                MfaChallenge.issue(userId, tenantId, tokenHash, Instant.now(), Duration.ofMinutes(5));

        challenge.consume(Instant.now());

        assertThat(challenge.isConsumed()).isTrue();
    }

    @Test
    void consumingAnAlreadyConsumedChallengeThrows() {
        MfaChallenge challenge =
                MfaChallenge.issue(userId, tenantId, tokenHash, Instant.now(), Duration.ofMinutes(5));
        challenge.consume(Instant.now());

        assertThatThrownBy(() -> challenge.consume(Instant.now()))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);
    }

    @Test
    void consumingAnExpiredChallengeThrows() {
        MfaChallenge challenge = MfaChallenge.issue(
                userId, tenantId, tokenHash, Instant.now().minusSeconds(600), Duration.ofMinutes(5));

        assertThatThrownBy(() -> challenge.consume(Instant.now()))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void reconstituteRestoresAllFields() {
        MfaChallengeId id = MfaChallengeId.generate();
        Instant expiresAt = Instant.now().plusSeconds(300);
        Instant consumedAt = Instant.now();
        Instant createdAt = Instant.now().minusSeconds(60);

        MfaChallenge challenge = MfaChallenge.reconstitute(id, userId, tenantId, tokenHash, expiresAt, consumedAt, createdAt);

        assertThat(challenge.id()).isEqualTo(id);
        assertThat(challenge.userId()).isEqualTo(userId);
        assertThat(challenge.tenantId()).isEqualTo(tenantId);
        assertThat(challenge.tokenHash()).isEqualTo(tokenHash);
        assertThat(challenge.expiresAt()).isEqualTo(expiresAt);
        assertThat(challenge.consumedAt()).isEqualTo(consumedAt);
        assertThat(challenge.createdAt()).isEqualTo(createdAt);
    }

    @Test
    void equalityIsBasedOnId() {
        MfaChallenge challenge1 =
                MfaChallenge.issue(userId, tenantId, tokenHash, Instant.now(), Duration.ofMinutes(5));
        MfaChallenge challenge2 = MfaChallenge.reconstitute(
                challenge1.id(), userId, tenantId, tokenHash, challenge1.expiresAt(), null, challenge1.createdAt());

        assertThat(challenge1).isEqualTo(challenge2);
        assertThat(challenge1).hasSameHashCodeAs(challenge2);
    }
}
