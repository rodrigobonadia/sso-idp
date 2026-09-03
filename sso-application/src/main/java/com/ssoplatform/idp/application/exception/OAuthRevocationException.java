package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code RevokeTokenUseCase} for a {@code POST /revoke} request that cannot even be
 * evaluated - a missing {@code token} parameter, or a client authentication failure - never for
 * the token itself being invalid/unknown/belonging to another client, which RFC 7009 §2.2
 * requires be treated as a silent success (HTTP 200, no body) so a caller can never use this
 * endpoint to probe whether a given token value exists (see {@code RevokeTokenUseCase}'s Javadoc).
 * Mirrors {@link OAuthDeviceAuthorizationException}'s shape.
 *
 * <p>{@link #errorCode()} is one of {@code invalid_request} or {@code invalid_client}; only {@code
 * invalid_client} gets HTTP 401 with a {@code WWW-Authenticate: Basic} header - see {@code
 * RevocationController}.
 */
public class OAuthRevocationException extends ApplicationException {

    private final String errorCode;

    public OAuthRevocationException(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
