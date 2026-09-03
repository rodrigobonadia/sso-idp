package com.ssoplatform.idp.domain.mfa;

/** Thrown for an invalid {@link EmailOtpCredential} lifecycle transition (e.g. activating one that
 * is already active). Mirrors {@link TotpCredentialStateException}. */
public class EmailOtpCredentialStateException extends RuntimeException {

    public EmailOtpCredentialStateException(String message) {
        super(message);
    }
}
