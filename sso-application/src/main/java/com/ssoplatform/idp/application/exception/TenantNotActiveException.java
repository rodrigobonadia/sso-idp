package com.ssoplatform.idp.application.exception;

public class TenantNotActiveException extends ApplicationException {

    public TenantNotActiveException(String slug) {
        super("Tenant '" + slug + "' is not active");
    }
}
