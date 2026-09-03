package com.ssoplatform.idp.domain.mfa;

/** Thrown when an {@link EncryptedTotpSecret} is constructed from a blank value. */
public class InvalidEncryptedTotpSecretException extends RuntimeException {

    public InvalidEncryptedTotpSecretException(String message) {
        super(message);
    }
}
