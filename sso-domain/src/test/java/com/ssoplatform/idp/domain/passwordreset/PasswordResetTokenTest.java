package com.ssoplatform.idp.domain.passwordreset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class PasswordResetTokenTest {

    private static final UserId USER_ID = UserId.generate();
    private static final TokenHash TOKEN_HASH = TokenHash.of("some-hash-value");
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void issuingSetsExpiryToNowPlusValidity() {
        PasswordResetToken token = PasswordResetToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(1));

        assertThat(token.userId()).isEqualTo(USER_ID);
        assertThat(token.tokenHash()).isEqualTo(TOKEN_HASH);
        assertThat(token.expiresAt()).isEqualTo(NOW.plus(Duration.ofHours(1)));
        assertThat(token.createdAt()).isEqualTo(NOW);
        assertThat(token.isConsumed()).isFalse();
    }

    @Test
    void consumingAValidTokenMarksItConsumed() {
        PasswordResetToken token = PasswordResetToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(1));

        token.consume(NOW.plusSeconds(10));

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.consumedAt()).isEqualTo(NOW.plusSeconds(10));
    }

    @Test
    void rejectsConsumingTheSameTokenTwice() {
        PasswordResetToken token = PasswordResetToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(1));
        token.consume(NOW.plusSeconds(10));

        assertThatThrownBy(() -> token.consume(NOW.plusSeconds(20)))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);
    }

    @Test
    void rejectsConsumingAnExpiredToken() {
        PasswordResetToken token = PasswordResetToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(1));

        assertThatThrownBy(() -> token.consume(NOW.plus(Duration.ofHours(2))))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void isExpiredReflectsWhetherNowIsPastTheExpiryInstant() {
        PasswordResetToken token = PasswordResetToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(1));

        assertThat(token.isExpired(NOW.plus(Duration.ofMinutes(59)))).isFalse();
        assertThat(token.isExpired(NOW.plus(Duration.ofHours(2)))).isTrue();
    }

    @Test
    void reconstituteRestoresAnExistingToken() {
        var id = PasswordResetTokenId.generate();
        Instant expiresAt = NOW.plus(Duration.ofHours(1));
        Instant consumedAt = NOW.plusSeconds(5);

        PasswordResetToken token =
                PasswordResetToken.reconstitute(id, USER_ID, TOKEN_HASH, expiresAt, consumedAt, NOW);

        assertThat(token.id()).isEqualTo(id);
        assertThat(token.isConsumed()).isTrue();
        assertThat(token.expiresAt()).isEqualTo(expiresAt);
    }

    @Test
    void equalityIsBasedOnId() {
        PasswordResetToken token = PasswordResetToken.issue(USER_ID, TOKEN_HASH, NOW, Duration.ofHours(1));
        PasswordResetToken reloaded = PasswordResetToken.reconstitute(
                token.id(), token.userId(), token.tokenHash(), token.expiresAt(), null, token.createdAt());

        assertThat(token).isEqualTo(reloaded);
        assertThat(token).hasSameHashCodeAs(reloaded);
    }
}
