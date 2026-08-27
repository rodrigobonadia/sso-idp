package com.ssoplatform.idp.domain.user;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when an operation is requested that the user's current status does not allow. */
public class UserStateException extends DomainException {

    public UserStateException(String message) {
        super(message);
    }
}
