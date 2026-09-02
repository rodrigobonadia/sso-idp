package com.ssoplatform.idp.domain.resource;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when an operation is requested that the resource's current {@link ResourceStatus} does not allow. */
public class ResourceStateException extends DomainException {

    public ResourceStateException(String message) {
        super(message);
    }
}
