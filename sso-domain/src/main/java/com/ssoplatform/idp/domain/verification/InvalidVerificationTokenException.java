package com.ssoplatform.idp.domain.verification;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a raw verification token value received from a caller is blank or malformed. */
public class InvalidVerificationTokenException extends DomainException {

    public InvalidVerificationTokenException(String message) {
        super(message);
    }
}
