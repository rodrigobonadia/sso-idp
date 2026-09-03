package com.ssoplatform.idp.domain.mfa;

/** Thrown when attempting to consume a {@link RecoveryCode} that was already used. */
public class RecoveryCodeAlreadyConsumedException extends RuntimeException {

    public RecoveryCodeAlreadyConsumedException() {
        super("Recovery code has already been used");
    }
}
