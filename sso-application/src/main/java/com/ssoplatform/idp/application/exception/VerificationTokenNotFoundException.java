package com.ssoplatform.idp.application.exception;

/** Raised when no verification token matches the hash of a presented raw token value. */
public class VerificationTokenNotFoundException extends ApplicationException {

    public VerificationTokenNotFoundException() {
        super("No matching verification token found");
    }
}
