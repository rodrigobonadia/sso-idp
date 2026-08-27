package com.ssoplatform.idp.application.exception;

/**
 * Raised when a login attempt supplies the correct password for an account that has been
 * auto-locked after too many prior failed attempts.
 *
 * <p>Only ever thrown after password verification has already succeeded (see {@link
 * com.ssoplatform.idp.application.usecase.user.LoginUseCase}), so it never leaks account status
 * to someone who does not already know the password.
 */
public class AccountLockedException extends ApplicationException {

    public AccountLockedException() {
        super("This account is locked");
    }
}
