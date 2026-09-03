package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class EmailOtpCodeTest {

    private final UserId userId = UserId.generate();
    private final MfaChallengeId mfaChallengeId = MfaChallengeId.generate();
    private final EmailOtpCodeHash codeHash = EmailOtpCodeHash.of("$2a$12$somehash");

    @Test
    void issueForEnrollmentProducesAnUnconsumedEnrollmentConfirmationCodeWithNoChallengeId() {
        Instant now = Instant.now();

        EmailOtpCode code = EmailOtpCode.issueForEnrollment(userId, codeHash, now, Duration.ofMinutes(5));

        assertThat(code.id()).isNotNull();
        assertThat(code.userId()).isEqualTo(userId);
        assertThat(code.purpose()).isEqualTo(EmailOtpPurpose.ENROLLMENT_CONFIRMATION);
        assertThat(code.mfaChallengeId()).isEmpty();
        assertThat(code.codeHash()).isEqualTo(codeHash);
        assertThat(code.expiresAt()).isEqualTo(now.plus(Duration.ofMinutes(5)));
        assertThat(code.isConsumed()).isFalse();
        assertThat(code.failedAttempts()).isZero();
    }

    @Test
    void issueForChallengeProducesALoginChallengeCodeTiedToThatChallenge() {
        EmailOtpCode code =
                EmailOtpCode.issueForChallenge(userId, mfaChallengeId, codeHash, Instant.now(), Duration.ofMinutes(5));

        assertThat(code.purpose()).isEqualTo(EmailOtpPurpose.LOGIN_CHALLENGE);
        assertThat(code.mfaChallengeId()).contains(mfaChallengeId);
    }

    @Test
    void consumeMarksTheCodeAsUsed() {
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));

        code.consume(Instant.now());

        assertThat(code.isConsumed()).isTrue();
    }

    @Test
    void consumingAnAlreadyConsumedCodeThrows() {
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));
        code.consume(Instant.now());

        assertThatThrownBy(() -> code.consume(Instant.now()))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);
    }

    @Test
    void consumingAnExpiredCodeThrows() {
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(
                userId, codeHash, Instant.now().minusSeconds(600), Duration.ofMinutes(5));

        assertThatThrownBy(() -> code.consume(Instant.now()))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void recordFailedAttemptIncrementsTheCounter() {
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));

        code.recordFailedAttempt(Instant.now());

        assertThat(code.failedAttempts()).isEqualTo(1);
        assertThat(code.hasExceededMaxAttempts()).isFalse();
    }

    @Test
    void recordingTheFifthFailedAttemptExceedsTheLimitAndAnySubsequentCheckThrows() {
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));

        for (int i = 0; i < EmailOtpCode.MAX_FAILED_ATTEMPTS; i++) {
            code.recordFailedAttempt(Instant.now());
        }

        assertThat(code.failedAttempts()).isEqualTo(EmailOtpCode.MAX_FAILED_ATTEMPTS);
        assertThat(code.hasExceededMaxAttempts()).isTrue();
        assertThatThrownBy(() -> code.recordFailedAttempt(Instant.now()))
                .isInstanceOf(TooManyFailedEmailOtpAttemptsException.class);
        assertThatThrownBy(() -> code.consume(Instant.now()))
                .isInstanceOf(TooManyFailedEmailOtpAttemptsException.class);
    }

    @Test
    void expiryTakesPriorityOverTheAttemptLimitWhenBothWouldApply() {
        // A code that is both expired AND already past its attempt limit must still report
        // "expired" (mirrors MfaChallenge#consume's consumed-before-expired ordering, extended
        // here with a third condition: consumed, then expired, then attempt-limit-exceeded).
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));
        for (int i = 0; i < EmailOtpCode.MAX_FAILED_ATTEMPTS; i++) {
            code.recordFailedAttempt(Instant.now());
        }

        assertThatThrownBy(() -> code.consume(Instant.now().plusSeconds(1000)))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void reconstituteRestoresAllFields() {
        EmailOtpCodeId id = EmailOtpCodeId.generate();
        Instant expiresAt = Instant.now().plusSeconds(300);
        Instant consumedAt = Instant.now();
        Instant createdAt = Instant.now().minusSeconds(60);

        EmailOtpCode code = EmailOtpCode.reconstitute(
                id,
                userId,
                EmailOtpPurpose.LOGIN_CHALLENGE,
                mfaChallengeId,
                codeHash,
                expiresAt,
                consumedAt,
                2,
                createdAt);

        assertThat(code.id()).isEqualTo(id);
        assertThat(code.userId()).isEqualTo(userId);
        assertThat(code.purpose()).isEqualTo(EmailOtpPurpose.LOGIN_CHALLENGE);
        assertThat(code.mfaChallengeId()).contains(mfaChallengeId);
        assertThat(code.codeHash()).isEqualTo(codeHash);
        assertThat(code.expiresAt()).isEqualTo(expiresAt);
        assertThat(code.consumedAt()).isEqualTo(consumedAt);
        assertThat(code.failedAttempts()).isEqualTo(2);
        assertThat(code.createdAt()).isEqualTo(createdAt);
    }

    @Test
    void equalityIsBasedOnId() {
        EmailOtpCode code1 = EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));
        EmailOtpCode code2 = EmailOtpCode.reconstitute(
                code1.id(),
                userId,
                EmailOtpPurpose.ENROLLMENT_CONFIRMATION,
                null,
                codeHash,
                code1.expiresAt(),
                null,
                0,
                code1.createdAt());

        assertThat(code1).isEqualTo(code2);
        assertThat(code1).hasSameHashCodeAs(code2);
    }
}
