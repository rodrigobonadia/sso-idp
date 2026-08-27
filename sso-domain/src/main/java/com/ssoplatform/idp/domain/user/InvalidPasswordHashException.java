package com.ssoplatform.idp.domain.user;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidPasswordHashException extends DomainException {

    public InvalidPasswordHashException(String message) {
        super(message);
    }
}
