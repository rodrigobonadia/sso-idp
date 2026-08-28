package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code AuthorizeUseCase} when the presented {@code client_id} does not resolve to a
 * client at all, or resolves to a client that belongs to a DIFFERENT tenant than the one the
 * current request's subdomain resolved to. Both cases are collapsed into this single exception,
 * deliberately, with the same generic message - the request must never reveal whether a client_id
 * exists at all, only in the wrong tenant, the same enumeration-safety reasoning {@code
 * LoginUseCase} already applies to e-mail/password combinations.
 *
 * <p>This exception is one of exactly two ({@link RedirectUriNotRegisteredException} is the other)
 * that {@code AuthorizeController} must NOT translate into a redirect back to the client: at the
 * point this is thrown, no {@code redirect_uri} has been validated as belonging to a real,
 * correctly-scoped client yet, so there is no target that can be trusted to receive an error
 * response (RFC 6749 §4.1.2.1) - the resource owner sees a rendered error page instead.
 */
public class OAuthClientNotFoundException extends ApplicationException {

    public OAuthClientNotFoundException() {
        super("No usable OAuth client found for the given client_id in this tenant");
    }
}
