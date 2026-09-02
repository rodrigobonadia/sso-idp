package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code GetUserInfoUseCase} for every {@code GET /userinfo} bearer-token failure -
 * missing header, malformed token, a token that fails {@code JwtVerifier} verification for any
 * reason, or a token whose {@code sub} no longer resolves to a real user. {@link #errorCode()} is
 * one of the {@code error} values RFC 6750 §3.1 defines for a protected-resource request ({@code
 * invalid_request}, {@code invalid_token}); {@code UserInfoController} catches this single
 * exception type and renders the corresponding {@code WWW-Authenticate: Bearer error="..."}
 * challenge with HTTP 401, mirroring how {@code OAuthTokenException} already carries its RFC 6749
 * error code as data rather than one subclass per error value.
 */
public class InvalidBearerTokenException extends ApplicationException {

    private final String errorCode;

    public InvalidBearerTokenException(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
