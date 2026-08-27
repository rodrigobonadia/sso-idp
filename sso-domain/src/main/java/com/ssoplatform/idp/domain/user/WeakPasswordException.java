package com.ssoplatform.idp.domain.user;

import com.ssoplatform.idp.domain.shared.DomainException;

public class WeakPasswordException extends DomainException {

    public WeakPasswordException(String message) {
        super(message);
    }
}
