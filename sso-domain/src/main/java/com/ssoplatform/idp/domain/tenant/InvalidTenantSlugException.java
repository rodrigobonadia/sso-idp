package com.ssoplatform.idp.domain.tenant;

import com.ssoplatform.idp.domain.shared.DomainException;

public class InvalidTenantSlugException extends DomainException {

    public InvalidTenantSlugException(String message) {
        super(message);
    }
}
