package com.ssoplatform.idp.application.exception;

/**
 * Raised when a login attempt's e-mail/password combination is wrong.
 *
 * <p>Deliberately carries the exact same message regardless of whether the e-mail doesn't exist
 * for the tenant or exists but the password is wrong, so that a failed attempt never lets a
 * caller distinguish "no such account" from "wrong password" (account enumeration).
 */
public class InvalidCredentialsException extends ApplicationException {

    public InvalidCredentialsException() {
        super("Invalid e-mail or password");
    }
}
