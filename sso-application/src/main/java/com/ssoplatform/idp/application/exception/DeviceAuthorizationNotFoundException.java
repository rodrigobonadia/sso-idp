package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code FindDeviceAuthorizationUseCase}/{@code DecideDeviceAuthorizationUseCase} when
 * the presented {@code user_code} does not resolve to a device code that is currently {@code
 * PENDING}, unexpired, and in this tenant. Deliberately a single outcome collapsing "no such
 * code", "wrong tenant", "expired", and "already approved/denied/redeemed" into one message - the
 * same enumeration-safety reasoning {@code TokenUseCase} documents for {@code invalid_grant} -
 * since this is a low-entropy, human-typed code, and a malicious caller should not be able to
 * learn anything more from the verification page's response than "try again".
 */
public class DeviceAuthorizationNotFoundException extends ApplicationException {

    public DeviceAuthorizationNotFoundException() {
        super("This code is invalid or has expired");
    }
}
