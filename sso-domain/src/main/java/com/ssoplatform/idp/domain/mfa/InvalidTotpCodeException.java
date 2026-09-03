package com.ssoplatform.idp.domain.mfa;

/** Thrown when a candidate TOTP code does not have the required 6-digit numeric shape. */
public class InvalidTotpCodeException extends RuntimeException {

    public InvalidTotpCodeException(String message) {
        super(message);
    }
}
