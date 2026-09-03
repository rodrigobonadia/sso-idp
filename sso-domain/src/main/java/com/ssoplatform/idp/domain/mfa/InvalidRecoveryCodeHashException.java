package com.ssoplatform.idp.domain.mfa;

/** Thrown when a {@link RecoveryCodeHash} is constructed from a blank value. */
public class InvalidRecoveryCodeHashException extends RuntimeException {

    public InvalidRecoveryCodeHashException(String message) {
        super(message);
    }
}
