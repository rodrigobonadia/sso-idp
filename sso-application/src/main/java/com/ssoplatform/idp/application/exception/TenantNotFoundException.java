package com.ssoplatform.idp.application.exception;

import java.util.UUID;

public class TenantNotFoundException extends ApplicationException {

    public TenantNotFoundException(UUID tenantId) {
        super("No tenant found with id '" + tenantId + "'");
    }
}
