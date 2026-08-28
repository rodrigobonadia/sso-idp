package com.ssoplatform.idp.domain.signingkey;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidPublicKeyMaterialException extends DomainException {

    public InvalidPublicKeyMaterialException(String message) {
        super(message);
    }
}
