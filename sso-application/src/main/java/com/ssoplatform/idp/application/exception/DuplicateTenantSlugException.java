package com.ssoplatform.idp.application.exception;

public class DuplicateTenantSlugException extends ApplicationException {

    public DuplicateTenantSlugException(String slug) {
        super("A tenant with slug '" + slug + "' already exists");
    }
}
