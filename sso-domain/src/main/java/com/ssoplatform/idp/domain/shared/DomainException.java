package com.ssoplatform.idp.domain.shared;

/**
 * Base type for every exception raised by a business rule violation in the domain layer.
 * Framework/infrastructure code (HTTP controllers, JPA, etc.) is expected to translate
 * subclasses of this exception into the appropriate external representation
 * (HTTP status code, error payload, ...), never the other way around.
 */
public abstract class DomainException extends RuntimeException {

    protected DomainException(String message) {
        super(message);
    }
}
