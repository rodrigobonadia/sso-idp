package com.ssoplatform.idp.application.exception;

/**
 * Raised by {@code AuthorizeUseCase} when the presented {@code redirect_uri} is a well-formed URI
 * but is not one of the client's registered {@code redirect_uris} (exact-match comparison - see
 * {@code RedirectUri}'s Javadoc). See {@link OAuthClientNotFoundException}'s Javadoc for why
 * neither this exception nor that one is ever translated into a redirect back to the client: an
 * unregistered redirect target is exactly the value that must never be trusted enough to receive
 * an error response.
 */
public class RedirectUriNotRegisteredException extends ApplicationException {

    public RedirectUriNotRegisteredException() {
        super("The redirect_uri is not registered for this OAuth client");
    }
}
