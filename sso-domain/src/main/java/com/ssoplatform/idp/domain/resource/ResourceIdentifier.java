package com.ssoplatform.idp.domain.resource;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

/**
 * Value object for a {@link Resource}'s public identifier - the "audience" a Client Credentials
 * token is scoped to, and the value a {@code /token} request presents via the {@code resource}
 * request parameter (RFC 8707, "Resource Indicators for OAuth 2.0").
 *
 * <p>Validates the shape RFC 8707 section 2 requires: an absolute URI, with no fragment component
 * (the same "no fragment" rule {@link com.ssoplatform.idp.domain.oauth.RedirectUri} enforces, and
 * for the same reason - a fragment would never even reach the server). Unlike {@code RedirectUri},
 * no scheme restriction is applied: a resource identifier is a pure identifier/audience value,
 * never itself navigated to or redirected through, so schemes like {@code urn:} are legitimate
 * here even though they are rejected for redirect URIs.
 */
public final class ResourceIdentifier {

    private final String value;

    private ResourceIdentifier(String value) {
        this.value = value;
    }

    public static ResourceIdentifier of(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new InvalidResourceIdentifierException("Resource identifier must not be blank");
        }
        String trimmed = rawValue.trim();
        URI parsed;
        try {
            parsed = new URI(trimmed);
        } catch (URISyntaxException e) {
            throw new InvalidResourceIdentifierException("Resource identifier '" + rawValue + "' is not a valid URI");
        }
        if (!parsed.isAbsolute()) {
            throw new InvalidResourceIdentifierException(
                    "Resource identifier '" + rawValue + "' must be an absolute URI (must include a scheme)");
        }
        if (parsed.getFragment() != null) {
            throw new InvalidResourceIdentifierException(
                    "Resource identifier '" + rawValue + "' must not contain a fragment component");
        }
        return new ResourceIdentifier(trimmed);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ResourceIdentifier that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
