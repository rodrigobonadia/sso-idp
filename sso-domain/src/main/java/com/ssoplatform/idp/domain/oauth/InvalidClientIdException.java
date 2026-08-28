package com.ssoplatform.idp.domain.oauth;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a candidate {@link ClientId} value does not have a valid shape. */
public class InvalidClientIdException extends DomainException {

    public InvalidClientIdException(String message) {
        super(message);
    }
}
