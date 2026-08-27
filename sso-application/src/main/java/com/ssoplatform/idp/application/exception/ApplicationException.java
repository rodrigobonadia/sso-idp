package com.ssoplatform.idp.application.exception;

/**
 * Base type for use-case-level failures: invariants that can only be checked by orchestrating
 * one or more ports (e.g. "this slug is already taken"), as opposed to invariants a single
 * entity can enforce on its own (which live in {@code com.ssoplatform.idp.domain} instead).
 */
public abstract class ApplicationException extends RuntimeException {

    protected ApplicationException(String message) {
        super(message);
    }
}
