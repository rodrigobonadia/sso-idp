package com.ssoplatform.idp.domain.verification;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a persisted token hash value is blank - always a programming error, never user input. */
public class InvalidTokenHashException extends DomainException {

    public InvalidTokenHashException(String message) {
        super(message);
    }
}
