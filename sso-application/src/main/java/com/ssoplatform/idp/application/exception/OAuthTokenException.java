package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code TokenUseCase} for every {@code POST /token} validation failure. Unlike {@code
 * OAuthAuthorizationException} (which {@code AuthorizeController} turns into a redirect), a token
 * error per RFC 6749 §5.2 is ALWAYS returned directly to the client as a JSON body - {@code /token}
 * has no browser redirect step at all - so {@code TokenController} catches this single exception
 * type and renders {@code {"error": ..., "error_description": ...}} with the appropriate HTTP
 * status.
 *
 * <p>{@link #errorCode()} is one of the {@code error} values RFC 6749 §5.2 defines for the token
 * endpoint ({@code invalid_request}, {@code invalid_client}, {@code invalid_grant}, {@code
 * unauthorized_client}, {@code unsupported_grant_type}, {@code invalid_scope}). Exactly one code,
 * {@code invalid_client}, gets HTTP 401 with a {@code WWW-Authenticate: Basic} header (client
 * authentication itself failed); every other code gets HTTP 400 - {@code TokenController} is the
 * one place that distinguishes them, by checking {@link #errorCode()}, mirroring how a single
 * exception class already carries the RFC error code as data for {@code
 * OAuthAuthorizationException} rather than one subclass per error value.
 */
public class OAuthTokenException extends ApplicationException {

    private final String errorCode;

    public OAuthTokenException(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
