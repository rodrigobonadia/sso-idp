package com.ssoplatform.idp.application.exception;

/** Raised when confirming MFA enrollment (TOTP or, since Phase 4.2, e-mail OTP) but no pending
 * (unconfirmed) credential of that method exists for the user - enrollment must be started first. */
public class MfaEnrollmentNotFoundException extends ApplicationException {

    public MfaEnrollmentNotFoundException() {
        super("No pending MFA enrollment found - start enrollment first");
    }
}
