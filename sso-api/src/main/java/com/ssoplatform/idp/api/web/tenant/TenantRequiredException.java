package com.ssoplatform.idp.api.web.tenant;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Raised by a controller when it needs a tenant to operate (e.g. registration, login) but
 * {@link TenantContext} came up empty for the current request - typically a call to the
 * root domain or an unresolved/malformed subdomain, rather than to a tenant's own subdomain.
 *
 * <p>Deliberately not an {@code ApplicationException}: "this request wasn't even addressed to a
 * tenant" is a fact about the HTTP request itself, established before any use case runs, not a
 * failure of a use case's business rules - so it belongs to the web layer, same as
 * {@link TenantResolutionFilter} and {@link TenantContext} do.
 *
 * <p>Carries {@code @ResponseStatus(BAD_REQUEST)} so that MVC controllers, which don't have a
 * global exception-mapping advice (unlike {@code web.rest}'s {@code ApiExceptionHandler}), still
 * get a sensible HTTP status if this ever propagates uncaught; {@code ApiExceptionHandler}'s own
 * explicit handler still takes precedence for REST calls.
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class TenantRequiredException extends RuntimeException {

    public TenantRequiredException() {
        super("This request must be addressed to a tenant's subdomain");
    }
}
