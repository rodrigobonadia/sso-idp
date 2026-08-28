package com.ssoplatform.idp.domain.signingkey;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidKeyIdException extends DomainException {

    public InvalidKeyIdException(String message) {
        super(message);
    }
}
