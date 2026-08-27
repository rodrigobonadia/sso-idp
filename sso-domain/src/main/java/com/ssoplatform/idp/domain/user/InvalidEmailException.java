package com.ssoplatform.idp.domain.user;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidEmailException extends DomainException {

    public InvalidEmailException(String message) {
        super(message);
    }
}
