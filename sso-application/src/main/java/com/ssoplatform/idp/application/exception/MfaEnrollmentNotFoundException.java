package com.ssoplatform.idp.application.exception;

/** Raised when confirming TOTP enrollment but no pending (unconfirmed) credential exists for the
 * user - {@code EnrollTotpUseCase} must be called first. */
public class MfaEnrollmentNotFoundException extends ApplicationException {

    public MfaEnrollmentNotFoundException() {
        super("No pending TOTP enrollment found - start enrollment first");
    }
}
