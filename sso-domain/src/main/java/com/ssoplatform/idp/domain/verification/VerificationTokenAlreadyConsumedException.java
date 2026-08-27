package com.ssoplatform.idp.domain.verification;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a verification token that was already consumed is presented again - tokens are single-use. */
public class VerificationTokenAlreadyConsumedException extends DomainException {

    public VerificationTokenAlreadyConsumedException() {
        super("Verification token has already been used");
    }
}
