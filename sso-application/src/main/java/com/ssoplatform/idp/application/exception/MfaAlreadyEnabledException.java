package com.ssoplatform.idp.application.exception;

/** Raised when starting TOTP enrollment for a user who already has an ACTIVE credential -
 * disabling MFA first is required, so re-enrollment is always an explicit, deliberate action. */
public class MfaAlreadyEnabledException extends ApplicationException {

    public MfaAlreadyEnabledException() {
        super("MFA is already enabled for this account - disable it before enrolling again");
    }
}
