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
 * unauthorized_client}, {@code unsupported_grant_type}, {@code invalid_scope}), plus {@code
 * invalid_target} - RFC 8707 §2's dedicated value for a Client Credentials request naming a
 * {@code resource} the client cannot use, whether because it does not parse, does not exist, is
 * disabled, or the client holds no authorization for it - plus four values RFC 8628 §3.5 defines
 * specifically for the device code grant's polling loop: {@code authorization_pending} (the user
 * has not yet acted on the verification page), {@code slow_down} (the device is polling faster
 * than the interval this platform returned), {@code expired_token} (the device/user code pair
 * expired before being redeemed), and {@code access_denied} (the user explicitly clicked Deny).
 * Exactly one code, {@code invalid_client}, gets HTTP 401 with a {@code WWW-Authenticate: Basic}
 * header (client authentication itself failed); every other code - including all four RFC 8628
 * ones, which RFC 8628 §3.5 itself specifies get HTTP 400 as well - gets HTTP 400 -
 * {@code TokenController} is the one place that distinguishes them, by checking {@link
 * #errorCode()}, mirroring how a single exception class already carries the RFC error code as data
 * for {@code OAuthAuthorizationException} rather than one subclass per error value.
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
