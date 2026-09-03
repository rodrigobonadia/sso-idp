package com.ssoplatform.idp.domain.mfa;

import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * A single-use, short-lived token bridging the two HTTP calls of a two-step (password + second
 * factor) login: {@code LoginUseCase} issues one once the password check succeeds for a user with
 * an active second-factor credential, instead of establishing a session immediately. Exactly the
 * same shape as {@code PasswordResetToken} (down to reusing {@link TokenHash} and both consumption
 * exceptions from {@code domain.verification}), except it also remembers {@link #tenantId()} -
 * unlike a password-reset link (which is only ever emailed to one already-known address), the
 * second step of login has no other way to know which tenant the original attempt was scoped to.
 *
 * <p>Since Phase 4.2, also remembers {@link #method()} - which second factor this specific
 * challenge must be satisfied with (TOTP or e-mail OTP), decided once at issuance time based on
 * whichever credential was active for the user, and never re-derived later. See {@link
 * MfaMethod}'s Javadoc for why this is stored rather than re-checked at verification time.
 *
 * <p>Validity is deliberately much shorter than a password-reset token (5 minutes vs. 1 hour):
 * this token only ever needs to survive the time it takes a human to read a code (off their
 * authenticator app, or from an e-mail) and type it in, not the time it takes to notice and open
 * an e-mail asking them to start a whole separate flow.
 */
public final class MfaChallenge {

    private final MfaChallengeId id;
    private final UserId userId;
    private final TenantId tenantId;
    private final MfaMethod method;
    private final TokenHash tokenHash;
    private final Instant expiresAt;
    private Instant consumedAt;
    private final Instant createdAt;

    private MfaChallenge(
            MfaChallengeId id,
            UserId userId,
            TenantId tenantId,
            MfaMethod method,
            TokenHash tokenHash,
            Instant expiresAt,
            Instant consumedAt,
            Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.tenantId = tenantId;
        this.method = method;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.consumedAt = consumedAt;
        this.createdAt = createdAt;
    }

    /** Issues a brand-new challenge, valid from {@code now} for {@code validity}. */
    public static MfaChallenge issue(
            UserId userId, TenantId tenantId, MfaMethod method, TokenHash tokenHash, Instant now, Duration validity) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(method, "method must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(validity, "validity must not be null");
        return new MfaChallenge(
                MfaChallengeId.generate(), userId, tenantId, method, tokenHash, now.plus(validity), null, now);
    }

    /** Reconstitutes a challenge that already exists (used by persistence adapters). */
    public static MfaChallenge reconstitute(
            MfaChallengeId id,
            UserId userId,
            TenantId tenantId,
            MfaMethod method,
            TokenHash tokenHash,
            Instant expiresAt,
            Instant consumedAt,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(method, "method must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new MfaChallenge(id, userId, tenantId, method, tokenHash, expiresAt, consumedAt, createdAt);
    }

    /**
     * Marks the challenge as used. Throws if it was already consumed (single-use) or if {@code
     * now} is past {@link #expiresAt} - in that order, mirroring {@code PasswordResetToken#consume}.
     */
    public void consume(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (isConsumed()) {
            throw new VerificationTokenAlreadyConsumedException();
        }
        if (isExpired(now)) {
            throw new VerificationTokenExpiredException();
        }
        this.consumedAt = now;
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    public MfaChallengeId id() {
        return id;
    }

    public UserId userId() {
        return userId;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public MfaMethod method() {
        return method;
    }

    public TokenHash tokenHash() {
        return tokenHash;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public Instant consumedAt() {
        return consumedAt;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MfaChallenge that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
