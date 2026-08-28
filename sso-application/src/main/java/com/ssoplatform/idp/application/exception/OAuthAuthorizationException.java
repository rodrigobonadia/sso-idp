package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code AuthorizeUseCase} for every {@code /authorize} validation failure that happens
 * AFTER the {@code client_id} and {@code redirect_uri} have both already been confirmed valid and
 * registered (see {@link OAuthClientNotFoundException}/{@link RedirectUriNotRegisteredException}
 * for the two exceptions that can only be thrown BEFORE that point). By this point the redirect
 * target is trusted, so per RFC 6749 §4.1.2.1 the error belongs in a redirect back to the client -
 * {@code redirect_uri?error=<errorCode>&error_description=<message>&state=<state>} - never a page
 * rendered directly to the resource owner.
 *
 * <p>{@link #errorCode()} is always one of the {@code error} values RFC 6749 §4.1.2.1 defines for
 * the authorization endpoint ({@code unauthorized_client}, {@code unsupported_response_type},
 * {@code invalid_scope}, {@code invalid_request}) - deliberately a single exception class carrying
 * the code as data, rather than one subclass per RFC error value: {@code AuthorizeController} only
 * ever needs the code and description to build the redirect, so a class hierarchy here would add
 * no behavior, only ceremony.
 */
public class OAuthAuthorizationException extends ApplicationException {

    private final String errorCode;

    public OAuthAuthorizationException(String errorCode, String errorDescription) {
        super(errorDescription);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
