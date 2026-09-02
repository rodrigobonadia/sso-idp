package com.ssoplatform.idp.domain.resource;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a candidate {@link ResourceIdentifier} value does not have a valid shape. */
public class InvalidResourceIdentifierException extends DomainException {

    public InvalidResourceIdentifierException(String message) {
        super(message);
    }
}
