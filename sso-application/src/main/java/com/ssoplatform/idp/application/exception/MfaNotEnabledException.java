package com.ssoplatform.idp.application.exception;

/** Raised when trying to disable MFA (or otherwise act on an active credential) for a user who
 * does not have one. */
public class MfaNotEnabledException extends ApplicationException {

    public MfaNotEnabledException() {
        super("MFA is not enabled for this account");
    }
}
