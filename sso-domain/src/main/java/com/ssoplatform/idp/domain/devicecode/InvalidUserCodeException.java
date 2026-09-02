package com.ssoplatform.idp.domain.devicecode;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a raw user code value received from a caller is blank, malformed, or the wrong length. */
public class InvalidUserCodeException extends DomainException {

    public InvalidUserCodeException(String message) {
        super(message);
    }
}
