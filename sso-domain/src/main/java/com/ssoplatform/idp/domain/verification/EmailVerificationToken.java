package com.ssoplatform.idp.domain.verification;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * A single-use, time-limited token proving a user has clicked the link sent to their e-mail
 * address. Encapsulates its own consumption rule ({@link #consume(Instant)}) so that "a token can
 * only ever be used once, and only before it expires" cannot be bypassed by any caller.
 *
 * <p>Only the {@link TokenHash} is held here, never the raw token value - the same reason
 * {@code User} only ever holds a {@code HashedPassword}, never a {@code RawPassword}.
 */
public final class EmailVerificationToken {

    private final VerificationTokenId id;
    private final UserId userId;
    private final TokenHash tokenHash;
    private final Instant expiresAt;
    private Instant consumedAt;
    private final Instant createdAt;

    private EmailVerificationToken(
            VerificationTokenId id,
            UserId userId,
            TokenHash tokenHash,
            Instant expiresAt,
            Instant consumedAt,
            Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.consumedAt = consumedAt;
        this.createdAt = createdAt;
    }

    /** Issues a brand-new token, valid from {@code now} for {@code validity}. */
    public static EmailVerificationToken issue(UserId userId, TokenHash tokenHash, Instant now, Duration validity) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(validity, "validity must not be null");
        return new EmailVerificationToken(VerificationTokenId.generate(), userId, tokenHash, now.plus(validity), null, now);
    }

    /** Reconstitutes a token that already exists (used by persistence adapters). */
    public static EmailVerificationToken reconstitute(
            VerificationTokenId id,
            UserId userId,
            TokenHash tokenHash,
            Instant expiresAt,
            Instant consumedAt,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new EmailVerificationToken(id, userId, tokenHash, expiresAt, consumedAt, createdAt);
    }

    /**
     * Marks the token as used. Throws if it was already consumed (single-use) or if {@code now}
     * is past {@link #expiresAt} - in that order, since "already used" is a more specific and
     * usually more actionable message than "expired" for a token that happens to be both.
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

    public VerificationTokenId id() {
        return id;
    }

    public UserId userId() {
        return userId;
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
        if (!(o instanceof EmailVerificationToken that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
