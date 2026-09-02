package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code RequestDeviceAuthorizationUseCase} for every {@code POST /device_authorization}
 * validation failure (RFC 8628 §3.1's device authorization request). Mirrors {@link
 * OAuthTokenException} exactly in shape and in how {@code DeviceAuthorizationController} renders
 * it - a JSON {@code {"error": ..., "error_description": ...}} body, since this endpoint (like
 * {@code /token}) never redirects a browser anywhere - kept as a separate type rather than reusing
 * {@link OAuthTokenException} so each endpoint's own Javadoc and catch block stay scoped to the
 * error codes that endpoint can actually produce.
 *
 * <p>{@link #errorCode()} is one of {@code invalid_request}, {@code invalid_client}, {@code
 * invalid_scope}, or {@code unauthorized_client}. Exactly {@code invalid_client} gets HTTP 401 with
 * a {@code WWW-Authenticate: Basic} header; every other code gets HTTP 400 - see {@code
 * DeviceAuthorizationController}.
 */
public class OAuthDeviceAuthorizationException extends ApplicationException {

    private final String errorCode;

    public OAuthDeviceAuthorizationException(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
