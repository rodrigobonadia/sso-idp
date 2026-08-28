package com.ssoplatform.idp.domain.signingkey;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when an operation is requested that the key's current {@link SigningKeyStatus} does not allow. */
public class SigningKeyStateException extends DomainException {

    public SigningKeyStateException(String message) {
        super(message);
    }
}
