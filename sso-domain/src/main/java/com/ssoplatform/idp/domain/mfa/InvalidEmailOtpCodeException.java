package com.ssoplatform.idp.domain.mfa;

/** Thrown when a candidate e-mail OTP code does not have the expected shape. */
public class InvalidEmailOtpCodeException extends RuntimeException {

    public InvalidEmailOtpCodeException(String message) {
        super(message);
    }
}
