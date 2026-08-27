package com.ssoplatform.idp.domain.verification;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a verification token is presented for consumption after its expiry instant. */
public class VerificationTokenExpiredException extends DomainException {

    public VerificationTokenExpiredException() {
        super("Verification token has expired");
    }
}
