package com.ssoplatform.idp.domain.mfa;

import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * A single, short-lived e-mail OTP code instance - either confirming enrollment ({@link
 * EmailOtpPurpose#ENROLLMENT_CONFIRMATION}) or satisfying one specific login challenge ({@link
 * EmailOtpPurpose#LOGIN_CHALLENGE}, tied to exactly one {@link MfaChallenge} via {@link
 * #mfaChallengeId()}). A fresh row is created every time a code is needed - "resending" a code is
 * simply re-running whatever action needed one in the first place ({@code
 * EnableEmailOtpUseCase}/{@code LoginUseCase}), which naturally supersedes any earlier still-live
 * code for the same purpose (see those use cases for how stale rows are cleaned up).
 *
 * <p>Only {@link #codeHash()} is ever persisted, never the raw code - same reasoning as {@link
 * RecoveryCode}: a candidate cannot be looked up by hash equality since BCrypt hashes are salted
 * (see {@code EmailOtpCodeHasher}), so the use case verifying a code must load the specific row it
 * expects (by {@code mfaChallengeId}, or the latest {@code ENROLLMENT_CONFIRMATION} row for the
 * user) and check the candidate against its hash.
 *
 * <p><b>Why this needs an attempt limit that {@link MfaChallenge}/{@link TotpCredential}'s
 * verification path does not:</b> a TOTP code rotates every 30 seconds, so even with no explicit
 * cap, an attacker only ever gets a handful of guesses against any one specific correct value
 * before it stops being correct - brute-forcing a 1-in-1,000,000 code in that window is
 * impractical. An e-mailed code, by contrast, is the SAME static value for its entire validity
 * window (5 minutes, matching {@code LoginUseCase.MFA_CHALLENGE_VALIDITY}) - without a limit, an
 * attacker who has somehow obtained a live challenge token gets many rapid-fire guesses at 1 in a
 * million odds before the code naturally expires. Capping wrong attempts at {@link
 * #MAX_FAILED_ATTEMPTS} closes that gap (matching NIST SP 800-63B's guidance to throttle OTP
 * verification): once exceeded, the code is permanently dead - even if not yet time-expired - and
 * the legitimate user must request a fresh one, which is cheap and always available to them.
 */
public final class EmailOtpCode {

    /** See this class's Javadoc for why an e-mailed code needs this and a TOTP code does not. */
    public static final int MAX_FAILED_ATTEMPTS = 5;

    private final EmailOtpCodeId id;
    private final UserId userId;
    private final EmailOtpPurpose purpose;
    private final MfaChallengeId mfaChallengeId;
    private final EmailOtpCodeHash codeHash;
    private final Instant expiresAt;
    private Instant consumedAt;
    private int failedAttempts;
    private final Instant createdAt;

    private EmailOtpCode(
            EmailOtpCodeId id,
            UserId userId,
            EmailOtpPurpose purpose,
            MfaChallengeId mfaChallengeId,
            EmailOtpCodeHash codeHash,
            Instant expiresAt,
            Instant consumedAt,
            int failedAttempts,
            Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.purpose = purpose;
        this.mfaChallengeId = mfaChallengeId;
        this.codeHash = codeHash;
        this.expiresAt = expiresAt;
        this.consumedAt = consumedAt;
        this.failedAttempts = failedAttempts;
        this.createdAt = createdAt;
    }

    /** Issues a fresh code confirming a still-pending {@link EmailOtpCredential} enrollment. */
    public static EmailOtpCode issueForEnrollment(
            UserId userId, EmailOtpCodeHash codeHash, Instant now, Duration validity) {
        return new EmailOtpCode(
                EmailOtpCodeId.generate(),
                requireNonNull(userId, "userId"),
                EmailOtpPurpose.ENROLLMENT_CONFIRMATION,
                null,
                requireNonNull(codeHash, "codeHash"),
                requireNonNull(now, "now").plus(requireNonNull(validity, "validity")),
                null,
                0,
                now);
    }

    /** Issues a fresh code satisfying one specific login challenge. */
    public static EmailOtpCode issueForChallenge(
            UserId userId, MfaChallengeId mfaChallengeId, EmailOtpCodeHash codeHash, Instant now, Duration validity) {
        return new EmailOtpCode(
                EmailOtpCodeId.generate(),
                requireNonNull(userId, "userId"),
                EmailOtpPurpose.LOGIN_CHALLENGE,
                requireNonNull(mfaChallengeId, "mfaChallengeId"),
                requireNonNull(codeHash, "codeHash"),
                requireNonNull(now, "now").plus(requireNonNull(validity, "validity")),
                null,
                0,
                now);
    }

    /** Reconstitutes a code that already exists (used by persistence adapters). */
    public static EmailOtpCode reconstitute(
            EmailOtpCodeId id,
            UserId userId,
            EmailOtpPurpose purpose,
            MfaChallengeId mfaChallengeId,
            EmailOtpCodeHash codeHash,
            Instant expiresAt,
            Instant consumedAt,
            int failedAttempts,
            Instant createdAt) {
        return new EmailOtpCode(
                requireNonNull(id, "id"),
                requireNonNull(userId, "userId"),
                requireNonNull(purpose, "purpose"),
                mfaChallengeId,
                requireNonNull(codeHash, "codeHash"),
                requireNonNull(expiresAt, "expiresAt"),
                consumedAt,
                failedAttempts,
                requireNonNull(createdAt, "createdAt"));
    }

    /** Marks the code as used after a correct match. Throws if it is no longer verifiable. */
    public void consume(Instant now) {
        assertVerifiable(now);
        this.consumedAt = now;
    }

    /** Records a wrong guess. Throws if it is no longer verifiable (including, redundantly but
     * safely, if this very call would be the one to exceed the limit - see {@link
     * #assertVerifiable}, which checks the count BEFORE incrementing). */
    public void recordFailedAttempt(Instant now) {
        assertVerifiable(now);
        this.failedAttempts++;
    }

    /** Throws the appropriate exception if this code can no longer be checked against a
     * candidate - consumed, expired, or already at the attempt limit, in that priority order
     * (mirrors {@link MfaChallenge#consume}'s consumed-before-expired ordering). */
    private void assertVerifiable(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (isConsumed()) {
            throw new VerificationTokenAlreadyConsumedException();
        }
        if (isExpired(now)) {
            throw new VerificationTokenExpiredException();
        }
        if (hasExceededMaxAttempts()) {
            throw new TooManyFailedEmailOtpAttemptsException();
        }
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    public boolean hasExceededMaxAttempts() {
        return failedAttempts >= MAX_FAILED_ATTEMPTS;
    }

    public EmailOtpCodeId id() {
        return id;
    }

    public UserId userId() {
        return userId;
    }

    public EmailOtpPurpose purpose() {
        return purpose;
    }

    /** Empty for an {@link EmailOtpPurpose#ENROLLMENT_CONFIRMATION} code - only a {@link
     * EmailOtpPurpose#LOGIN_CHALLENGE} code is tied to a specific challenge. */
    public Optional<MfaChallengeId> mfaChallengeId() {
        return Optional.ofNullable(mfaChallengeId);
    }

    public EmailOtpCodeHash codeHash() {
        return codeHash;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public Instant consumedAt() {
        return consumedAt;
    }

    public int failedAttempts() {
        return failedAttempts;
    }

    public Instant createdAt() {
        return createdAt;
    }

    private static <T> T requireNonNull(T value, String name) {
        return Objects.requireNonNull(value, name + " must not be null");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailOtpCode that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
