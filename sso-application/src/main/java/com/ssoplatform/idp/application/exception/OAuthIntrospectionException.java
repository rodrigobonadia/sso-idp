package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code IntrospectTokenUseCase} for a {@code POST /introspect} request that cannot even
 * be evaluated - a missing {@code token} parameter, or a client authentication failure - never for
 * the token itself being invalid/expired/unknown, which is reported as {@code {"active": false}}
 * per RFC 7662 §2.2, not as an exception (see {@code IntrospectTokenUseCase}'s Javadoc for the
 * enumeration-safety reasoning). Mirrors {@link OAuthDeviceAuthorizationException}'s shape.
 *
 * <p>{@link #errorCode()} is one of {@code invalid_request} or {@code invalid_client}; only {@code
 * invalid_client} gets HTTP 401 with a {@code WWW-Authenticate: Basic} header - see {@code
 * IntrospectionController}.
 */
public class OAuthIntrospectionException extends ApplicationException {

    private final String errorCode;

    public OAuthIntrospectionException(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
