package com.ssoplatform.idp.domain.mfa;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.Objects;

/**
 * A user's enrolled e-mail-based OTP second factor (Phase 4.2). Mirrors {@link TotpCredential}'s
 * shape and two-step enrollment lifecycle almost exactly, with one deliberate difference: there is
 * no secret to encrypt and store here at all. Unlike TOTP (a shared secret the credential must
 * hold so future codes can be verified against it), an e-mail OTP code is a fresh random value
 * generated and hashed anew every single time one is needed (see {@link EmailOtpCode}) - this
 * credential only ever records whether the method is enabled, never any code itself.
 *
 * <p>Enrollment is still two-step for the same reason TOTP's is: {@link #enable} produces a
 * {@link EmailOtpCredentialStatus#PENDING_ACTIVATION} row, and only {@link #activate} - once the
 * user has proven they actually received and read a real confirmation code at their registered
 * address - makes it usable to satisfy a login challenge. This matters even more here than for
 * TOTP: a user's e-mail address was last proven reachable at registration time, possibly long ago
 * (a mailbox can be deleted, a domain can expire), so re-confirming live access at enable time is
 * the whole point, not a formality.
 *
 * <p>A user may have at most one of {@code TotpCredential}/{@code EmailOtpCredential} ACTIVE at a
 * time - see {@code EnableEmailOtpUseCase}/{@code EnrollTotpUseCase} for where that invariant is
 * enforced (deliberately at the application layer, not here, since it requires looking at a
 * SIBLING aggregate this class has no reference to).
 */
public final class EmailOtpCredential {

    private final EmailOtpCredentialId id;
    private final UserId userId;
    private EmailOtpCredentialStatus status;
    private final Instant createdAt;
    private Instant activatedAt;

    private EmailOtpCredential(
            EmailOtpCredentialId id,
            UserId userId,
            EmailOtpCredentialStatus status,
            Instant createdAt,
            Instant activatedAt) {
        this.id = id;
        this.userId = userId;
        this.status = status;
        this.createdAt = createdAt;
        this.activatedAt = activatedAt;
    }

    /** Starts enrollment for a brand-new (or restarted, if the previous attempt was never
     * confirmed) e-mail OTP credential. */
    public static EmailOtpCredential enable(UserId userId, Instant now) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(now, "now must not be null");
        return new EmailOtpCredential(
                EmailOtpCredentialId.generate(), userId, EmailOtpCredentialStatus.PENDING_ACTIVATION, now, null);
    }

    /** Reconstitutes a credential that already exists (used by persistence adapters). */
    public static EmailOtpCredential reconstitute(
            EmailOtpCredentialId id,
            UserId userId,
            EmailOtpCredentialStatus status,
            Instant createdAt,
            Instant activatedAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new EmailOtpCredential(id, userId, status, createdAt, activatedAt);
    }

    /** Confirms enrollment: the user has proven they received a real code at their registered address. */
    public void activate(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (status == EmailOtpCredentialStatus.ACTIVE) {
            throw new EmailOtpCredentialStateException("Email OTP credential is already active");
        }
        this.status = EmailOtpCredentialStatus.ACTIVE;
        this.activatedAt = now;
    }

    public boolean isActive() {
        return status == EmailOtpCredentialStatus.ACTIVE;
    }

    public EmailOtpCredentialId id() {
        return id;
    }

    public UserId userId() {
        return userId;
    }

    public EmailOtpCredentialStatus status() {
        return status;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant activatedAt() {
        return activatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof EmailOtpCredential that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
