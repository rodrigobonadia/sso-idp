package com.ssoplatform.idp.domain.devicecode;

import com.ssoplatform.idp.domain.shared.DomainException;

/** Raised when an operation is requested that the device code's current {@link DeviceCodeStatus} does not allow. */
public class DeviceCodeStateException extends DomainException {

    public DeviceCodeStateException(String message) {
        super(message);
    }
}
