package com.ssoplatform.idp.domain.user;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import java.util.Objects;

/**
 * A user account, always scoped to exactly one {@link com.ssoplatform.idp.domain.tenant.Tenant}.
 *
 * <p>Encapsulates the account lifecycle (e-mail verification, lockout after repeated failed
 * logins, administrative disable) so that these security-sensitive invariants cannot be
 * bypassed by callers in the application or infrastructure layers.
 */
public final class User {

    /** Number of consecutive failed login attempts after which the account is auto-locked. */
    public static final int MAX_FAILED_LOGIN_ATTEMPTS = 5;

    private final UserId id;
    private final TenantId tenantId;
    private final Email email;
    private HashedPassword passwordHash;
    private UserStatus status;
    private int failedLoginAttempts;
    private final Instant createdAt;

    private User(
            UserId id,
            TenantId tenantId,
            Email email,
            HashedPassword passwordHash,
            UserStatus status,
            int failedLoginAttempts,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.email = email;
        this.passwordHash = passwordHash;
        this.status = status;
        this.failedLoginAttempts = failedLoginAttempts;
        this.createdAt = createdAt;
    }

    /** Registers a brand-new user, pending e-mail verification. */
    public static User register(TenantId tenantId, Email email, HashedPassword passwordHash) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(email, "email must not be null");
        Objects.requireNonNull(passwordHash, "passwordHash must not be null");
        return new User(
                UserId.generate(), tenantId, email, passwordHash, UserStatus.PENDING_VERIFICATION, 0, Instant.now());
    }

    /** Reconstitutes a user that already exists (used by persistence adapters). */
    public static User reconstitute(
            UserId id,
            TenantId tenantId,
            Email email,
            HashedPassword passwordHash,
            UserStatus status,
            int failedLoginAttempts,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(email, "email must not be null");
        Objects.requireNonNull(passwordHash, "passwordHash must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        if (failedLoginAttempts < 0) {
            throw new IllegalArgumentException("failedLoginAttempts must not be negative");
        }
        return new User(id, tenantId, email, passwordHash, status, failedLoginAttempts, createdAt);
    }

    public void verifyEmail() {
        if (status != UserStatus.PENDING_VERIFICATION) {
            throw new UserStateException("User '" + email + "' is not pending verification");
        }
        this.status = UserStatus.ACTIVE;
    }

    public void changePassword(HashedPassword newPasswordHash) {
        Objects.requireNonNull(newPasswordHash, "newPasswordHash must not be null");
        if (status == UserStatus.DISABLED) {
            throw new UserStateException("Cannot change password of a disabled user");
        }
        this.passwordHash = newPasswordHash;
    }

    /** Records a failed authentication attempt, auto-locking the account past the threshold. */
    public void recordFailedLogin() {
        this.failedLoginAttempts++;
        if (failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS && status == UserStatus.ACTIVE) {
            this.status = UserStatus.LOCKED;
        }
    }

    /** Records a successful authentication, resetting the failed-attempt counter. */
    public void recordSuccessfulLogin() {
        if (status != UserStatus.ACTIVE) {
            throw new UserStateException("User '" + email + "' cannot authenticate in status " + status);
        }
        this.failedLoginAttempts = 0;
    }

    public void lock() {
        if (status == UserStatus.LOCKED) {
            throw new UserStateException("User '" + email + "' is already locked");
        }
        this.status = UserStatus.LOCKED;
    }

    public void unlock() {
        if (status != UserStatus.LOCKED) {
            throw new UserStateException("User '" + email + "' is not locked");
        }
        this.status = UserStatus.ACTIVE;
        this.failedLoginAttempts = 0;
    }

    public void disable() {
        if (status == UserStatus.DISABLED) {
            throw new UserStateException("User '" + email + "' is already disabled");
        }
        this.status = UserStatus.DISABLED;
    }

    public void enable() {
        if (status != UserStatus.DISABLED) {
            throw new UserStateException("User '" + email + "' is not disabled");
        }
        this.status = UserStatus.ACTIVE;
        this.failedLoginAttempts = 0;
    }

    public boolean canAuthenticate() {
        return status == UserStatus.ACTIVE;
    }

    public UserId id() {
        return id;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public Email email() {
        return email;
    }

    public HashedPassword passwordHash() {
        return passwordHash;
    }

    public UserStatus status() {
        return status;
    }

    public int failedLoginAttempts() {
        return failedLoginAttempts;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;
        return id.equals(user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
