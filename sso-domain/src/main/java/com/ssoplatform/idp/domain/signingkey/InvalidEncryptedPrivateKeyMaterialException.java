package com.ssoplatform.idp.domain.signingkey;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidEncryptedPrivateKeyMaterialException extends DomainException {

    public InvalidEncryptedPrivateKeyMaterialException(String message) {
        super(message);
    }
}
