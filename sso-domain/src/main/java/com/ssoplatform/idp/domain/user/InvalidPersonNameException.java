package com.ssoplatform.idp.domain.user;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidPersonNameException extends DomainException {

    public InvalidPersonNameException(String message) {
        super(message);
    }
}
