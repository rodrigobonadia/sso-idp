package com.ssoplatform.idp.domain.mfa;

/** Thrown when a candidate {@link EmailOtpCodeHash} value is blank. */
public class InvalidEmailOtpCodeHashException extends RuntimeException {

    public InvalidEmailOtpCodeHashException(String message) {
        super(message);
    }
}
