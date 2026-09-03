package com.ssoplatform.idp.domain.mfa;

/** Thrown for an invalid {@link TotpCredential} lifecycle transition (e.g. activating one that is
 * already active). Mirrors {@code SigningKeyStateException}. */
public class TotpCredentialStateException extends RuntimeException {

    public TotpCredentialStateException(String message) {
        super(message);
    }
}
