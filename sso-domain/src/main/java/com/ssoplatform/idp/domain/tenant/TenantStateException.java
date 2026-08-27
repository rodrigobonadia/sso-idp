package com.ssoplatform.idp.domain.tenant;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when a state transition is requested that the tenant's current status does not allow. */
public class TenantStateException extends DomainException {

    public TenantStateException(String message) {
        super(message);
    }
}
