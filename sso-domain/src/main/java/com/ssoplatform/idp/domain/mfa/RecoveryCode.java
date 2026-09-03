package com.ssoplatform.idp.domain.mfa;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.Objects;

/**
 * One of a user's single-use MFA recovery codes, issued in a batch of ten at TOTP enrollment
 * confirmation time. Unlike {@code PasswordResetToken}/{@code MfaChallenge}, a recovery code has
 * no expiry - it remains valid until consumed or until the whole batch is replaced (re-enrolling,
 * or an explicit regenerate action).
 *
 * <p>Only {@link #codeHash()} is ever persisted, never the raw code - see {@link RecoveryCodeHash}
 * for why this is a BCrypt hash (via {@code RecoveryCodeHasher}), not a {@code TokenHash}: because
 * BCrypt hashes are salted, a candidate code cannot be looked up by hash equality - the use case
 * verifying a recovery code must instead load all of a user's unconsumed codes and check the
 * candidate against each one's hash in turn (see {@code VerifyMfaRecoveryCodeChallengeUseCase}).
 */
public final class RecoveryCode {

    private final RecoveryCodeId id;
    private final UserId userId;
    private final RecoveryCodeHash codeHash;
    private Instant consumedAt;
    private final Instant createdAt;

    private RecoveryCode(
            RecoveryCodeId id, UserId userId, RecoveryCodeHash codeHash, Instant consumedAt, Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.codeHash = codeHash;
        this.consumedAt = consumedAt;
        this.createdAt = createdAt;
    }

    /** Issues a brand-new, unconsumed recovery code. */
    public static RecoveryCode issue(UserId userId, RecoveryCodeHash codeHash, Instant now) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(codeHash, "codeHash must not be null");
        Objects.requireNonNull(now, "now must not be null");
        return new RecoveryCode(RecoveryCodeId.generate(), userId, codeHash, null, now);
    }

    /** Reconstitutes a code that already exists (used by persistence adapters). */
    public static RecoveryCode reconstitute(
            RecoveryCodeId id, UserId userId, RecoveryCodeHash codeHash, Instant consumedAt, Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(codeHash, "codeHash must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new RecoveryCode(id, userId, codeHash, consumedAt, createdAt);
    }

    /** Marks the code as used. Throws if it was already consumed (single-use, no expiry to check). */
    public void consume(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (isConsumed()) {
            throw new RecoveryCodeAlreadyConsumedException();
        }
        this.consumedAt = now;
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public RecoveryCodeId id() {
        return id;
    }

    public UserId userId() {
        return userId;
    }

    public RecoveryCodeHash codeHash() {
        return codeHash;
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
        if (!(o instanceof RecoveryCode that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
