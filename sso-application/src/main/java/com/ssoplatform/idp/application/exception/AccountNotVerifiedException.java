package com.ssoplatform.idp.application.exception;

/**
 * Raised when a login attempt supplies the correct password for an account that has not yet
 * verified its e-mail address.
 *
 * <p>Only ever thrown after password verification has already succeeded (see {@link
 * com.ssoplatform.idp.application.usecase.user.LoginUseCase}), so it never leaks account status
 * to someone who does not already know the password.
 */
public class AccountNotVerifiedException extends ApplicationException {

    public AccountNotVerifiedException() {
        super("This account has not verified its e-mail address yet");
    }
}
