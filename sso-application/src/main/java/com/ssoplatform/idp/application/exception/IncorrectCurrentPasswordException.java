package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@link com.ssoplatform.idp.application.usecase.user.ChangePasswordUseCase} when the
 * caller's supplied current password does not match the one on file.
 *
 * <p>Unlike {@link InvalidCredentialsException} (login), there is no enumeration concern to guard
 * against here: the caller already holds an authenticated session for this exact user, so there is
 * nothing about "which account" left to protect - a specific, honest message is the more useful
 * response.
 */
public class IncorrectCurrentPasswordException extends ApplicationException {

    public IncorrectCurrentPasswordException() {
        super("Current password is incorrect");
    }
}
