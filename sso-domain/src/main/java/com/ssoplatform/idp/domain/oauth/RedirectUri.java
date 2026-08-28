package com.ssoplatform.idp.domain.oauth;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

/**
 * Value object for a single redirect URI registered against an {@link OAuthClient}.
 *
 * <p>Validates the shape recommended by RFC 6749 §3.1.2 and reinforced by OAuth 2.1: must be an
 * absolute URI (scheme + host present) and must not contain a fragment component (a fragment
 * would never even reach the server, so allowing one here would only hide a client
 * misconfiguration). Only {@code http}/{@code https} schemes are accepted for now - this project
 * only models confidential, server-side clients so far (see {@code architecture_decisions.md});
 * a public/native client's custom URI scheme (e.g. {@code myapp://callback}) is deliberately out
 * of scope until that client type is built.
 *
 * <p>{@link OAuthClient#isRedirectUriRegistered(RedirectUri)} always compares by exact value
 * equality, never by prefix/pattern matching - exact match is the OAuth 2.1-recommended defense
 * against open-redirect attacks via a registered URI's sub-path.
 */
public final class RedirectUri {

    private final String value;

    private RedirectUri(String value) {
        this.value = value;
    }

    public static RedirectUri of(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new InvalidRedirectUriException("Redirect URI must not be blank");
        }
        String trimmed = rawValue.trim();
        URI parsed;
        try {
            parsed = new URI(trimmed);
        } catch (URISyntaxException e) {
            throw new InvalidRedirectUriException("Redirect URI '" + rawValue + "' is not a valid URI");
        }
        if (!parsed.isAbsolute() || parsed.getHost() == null) {
            throw new InvalidRedirectUriException(
                    "Redirect URI '" + rawValue + "' must be an absolute URI with a scheme and host");
        }
        String scheme = parsed.getScheme().toLowerCase();
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new InvalidRedirectUriException(
                    "Redirect URI '" + rawValue + "' must use the http or https scheme");
        }
        if (parsed.getFragment() != null) {
            throw new InvalidRedirectUriException(
                    "Redirect URI '" + rawValue + "' must not contain a fragment component");
        }
        return new RedirectUri(trimmed);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RedirectUri that)) return false;
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
