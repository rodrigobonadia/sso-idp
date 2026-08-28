package com.ssoplatform.idp.domain.oauth;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when an operation is requested that the client's current {@link OAuthClientStatus} does not allow. */
public class OAuthClientStateException extends DomainException {

    public OAuthClientStateException(String message) {
        super(message);
    }
}
