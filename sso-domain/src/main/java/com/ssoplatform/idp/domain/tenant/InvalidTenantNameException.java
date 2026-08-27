package com.ssoplatform.idp.domain.tenant;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidTenantNameException extends DomainException {

    public InvalidTenantNameException(String message) {
        super(message);
    }
}
