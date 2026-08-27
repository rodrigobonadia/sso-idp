package com.ssoplatform.idp.domain.verification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class EmailVerificationTokenTest {

    private static final UserId USER_ID = UserId.generate();
    private static final TokenHash TOKEN_HASH = TokenHash.of("some-hash-value");
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void issuingSetsExpiryToNowPlusValidity() {
        EmailVerificationToken token = EmailVerificationToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(24));

        assertThat(token.userId()).isEqualTo(USER_ID);
        assertThat(token.tokenHash()).isEqualTo(TOKEN_HASH);
        assertThat(token.expiresAt()).isEqualTo(NOW.plus(Duration.ofHours(24)));
        assertThat(token.createdAt()).isEqualTo(NOW);
        assertThat(token.isConsumed()).isFalse();
    }

    @Test
    void consumingAValidTokenMarksItConsumed() {
        EmailVerificationToken token = EmailVerificationToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(24));

        token.consume(NOW.plusSeconds(10));

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.consumedAt()).isEqualTo(NOW.plusSeconds(10));
    }

    @Test
    void rejectsConsumingTheSameTokenTwice() {
        EmailVerificationToken token = EmailVerificationToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(24));
        token.consume(NOW.plusSeconds(10));

        assertThatThrownBy(() -> token.consume(NOW.plusSeconds(20)))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);
    }

    @Test
    void rejectsConsumingAnExpiredToken() {
        EmailVerificationToken token = EmailVerificationToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(24));

        assertThatThrownBy(() -> token.consume(NOW.plus(Duration.ofHours(25))))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void isExpiredReflectsWhetherNowIsPastTheExpiryInstant() {
        EmailVerificationToken token = EmailVerificationToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(24));

        assertThat(token.isExpired(NOW.plus(Duration.ofHours(23)))).isFalse();
        assertThat(token.isExpired(NOW.plus(Duration.ofHours(25)))).isTrue();
    }

    @Test
    void reconstituteRestoresAnExistingToken() {
        var id = VerificationTokenId.generate();
        Instant expiresAt = NOW.plus(Duration.ofHours(24));
        Instant consumedAt = NOW.plusSeconds(5);

        EmailVerificationToken token =
                EmailVerificationToken.reconstitute(id, USER_ID, TOKEN_HASH, expiresAt, consumedAt, NOW);

        assertThat(token.id()).isEqualTo(id);
        assertThat(token.isConsumed()).isTrue();
        assertThat(token.expiresAt()).isEqualTo(expiresAt);
    }

    @Test
    void equalityIsBasedOnId() {
        EmailVerificationToken token = EmailVerificationToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(24));
        EmailVerificationToken reloaded = EmailVerificationToken.reconstitute(
                token.id(), token.userId(), token.tokenHash(), token.expiresAt(), null, token.createdAt());

        assertThat(token).isEqualTo(reloaded);
        assertThat(token).hasSameHashCodeAs(reloaded);
    }
}
