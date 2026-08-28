package com.ssoplatform.idp.domain.oauth;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a candidate {@link RedirectUri} value is not a valid, absolute HTTP(S) URI. */
public class InvalidRedirectUriException extends DomainException {

    public InvalidRedirectUriException(String message) {
        super(message);
    }
}
