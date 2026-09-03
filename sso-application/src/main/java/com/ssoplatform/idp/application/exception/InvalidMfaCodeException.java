package com.ssoplatform.idp.application.exception;

/**
 * Raised when a submitted TOTP code or recovery code does not satisfy an MFA challenge. Unlike
 * {@link InvalidCredentialsException} (login), there is no enumeration concern to guard against:
 * an {@code MfaChallenge} token already commits the caller to one specific, already
 * password-verified user, so a specific, honest message is the more useful response - the same
 * reasoning as {@link IncorrectCurrentPasswordException}.
 */
public class InvalidMfaCodeException extends ApplicationException {

    public InvalidMfaCodeException() {
        super("The provided code is invalid");
    }
}
