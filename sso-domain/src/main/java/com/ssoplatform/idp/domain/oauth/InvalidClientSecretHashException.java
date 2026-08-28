package com.ssoplatform.idp.domain.oauth;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a candidate {@link ClientSecretHash} value is blank. */
public class InvalidClientSecretHashException extends DomainException {

    public InvalidClientSecretHashException(String message) {
        super(message);
    }
}
