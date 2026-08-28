package com.ssoplatform.idp.domain.authorization;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a PKCE {@code code_challenge} received from a client is blank or malformed. */
public class InvalidCodeChallengeException extends DomainException {

    public InvalidCodeChallengeException(String message) {
        super(message);
    }
}
