package com.ssoplatform.idp.domain.user;

/** Lifecycle status of a {@link User}. */
public enum UserStatus {

    /** Account created but the e-mail address has not been verified yet; cannot authenticate. */
    PENDING_VERIFICATION,

    /** Fully operational: the user can authenticate. */
    ACTIVE,

    /** Locked out automatically after too many failed login attempts. Requires unlocking. */
    LOCKED,

    /** Disabled by an administrator; cannot authenticate until re-enabled. */
    DISABLED
}
