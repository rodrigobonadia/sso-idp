package com.ssoplatform.idp.domain.mfa;

/** Thrown when a candidate recovery code does not have the expected shape. */
public class InvalidRecoveryCodeException extends RuntimeException {

    public InvalidRecoveryCodeException(String message) {
        super(message);
    }
}
