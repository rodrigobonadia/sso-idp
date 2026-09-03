package com.ssoplatform.idp.domain.mfa;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.Objects;

/**
 * A user's enrolled TOTP (RFC 6238) second factor. Exactly one credential exists per user - a
 * dedicated aggregate rather than fields on {@code User} itself, mirroring this codebase's
 * established pattern of separate aggregates for security-sensitive, independently-lifecycled
 * state ({@code RefreshToken}, {@code DeviceCode}, {@code SigningKey} are all separate from
 * {@code User}/{@code OAuthClient} the same way).
 *
 * <p>Enrollment is deliberately two-step: {@link #enroll} produces a {@link
 * TotpCredentialStatus#PENDING_ACTIVATION} credential, and only {@link #activate} - called once
 * the user has proven their authenticator app actually produces matching codes for this secret -
 * makes it usable to satisfy a login challenge. This prevents a broken enrollment (secret never
 * actually scanned, or scanned wrong) from ever locking a real user out of their own account.
 *
 * <p>The secret never appears here in plaintext - {@link #encryptedSecret()} is always already
 * encrypted by the time it reaches this entity (see {@link EncryptedTotpSecret}).
 */
public final class TotpCredential {

    private final TotpCredentialId id;
    private final UserId userId;
    private final EncryptedTotpSecret encryptedSecret;
    private TotpCredentialStatus status;
    private final Instant createdAt;
    private Instant activatedAt;

    private TotpCredential(
            TotpCredentialId id,
            UserId userId,
            EncryptedTotpSecret encryptedSecret,
            TotpCredentialStatus status,
            Instant createdAt,
            Instant activatedAt) {
        this.id = id;
        this.userId = userId;
        this.encryptedSecret = encryptedSecret;
        this.status = status;
        this.createdAt = createdAt;
        this.activatedAt = activatedAt;
    }

    /** Starts enrollment for a brand-new (or restarted, if the previous attempt was never
     * confirmed) TOTP secret. */
    public static TotpCredential enroll(UserId userId, EncryptedTotpSecret encryptedSecret, Instant now) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(encryptedSecret, "encryptedSecret must not be null");
        Objects.requireNonNull(now, "now must not be null");
        return new TotpCredential(
                TotpCredentialId.generate(), userId, encryptedSecret, TotpCredentialStatus.PENDING_ACTIVATION, now, null);
    }

    /** Reconstitutes a credential that already exists (used by persistence adapters). */
    public static TotpCredential reconstitute(
            TotpCredentialId id,
            UserId userId,
            EncryptedTotpSecret encryptedSecret,
            TotpCredentialStatus status,
            Instant createdAt,
            Instant activatedAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(encryptedSecret, "encryptedSecret must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new TotpCredential(id, userId, encryptedSecret, status, createdAt, activatedAt);
    }

    /** Confirms enrollment: the user has proven possession of a matching authenticator. */
    public void activate(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (status == TotpCredentialStatus.ACTIVE) {
            throw new TotpCredentialStateException("TOTP credential is already active");
        }
        this.status = TotpCredentialStatus.ACTIVE;
        this.activatedAt = now;
    }

    public boolean isActive() {
        return status == TotpCredentialStatus.ACTIVE;
    }

    public TotpCredentialId id() {
        return id;
    }

    public UserId userId() {
        return userId;
    }

    public EncryptedTotpSecret encryptedSecret() {
        return encryptedSecret;
    }

    public TotpCredentialStatus status() {
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
        if (!(o instanceof TotpCredential that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
