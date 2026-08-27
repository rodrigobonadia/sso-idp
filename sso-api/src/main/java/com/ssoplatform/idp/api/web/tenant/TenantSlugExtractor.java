package com.ssoplatform.idp.api.web.tenant;

import java.util.Locale;
import java.util.Optional;

/**
 * Pure logic (no Spring, no Servlet API) for extracting a tenant slug from an HTTP request's
 * host name, given the platform's configured base domain.
 *
 * <p>With {@code baseDomain = "localhost"}: host {@code acme.localhost} yields slug {@code acme};
 * host {@code localhost} itself (the base domain, no subdomain present) yields no tenant - that is
 * the platform's "global" scope; and a host that isn't a subdomain of the base domain at all
 * (e.g. an unrelated domain, or a raw IP address) also yields no tenant.
 *
 * <p>Kept as a standalone class, independent of {@link TenantResolutionFilter}, specifically so
 * this parsing logic can be unit-tested with plain JUnit - no Spring context, no servlet request
 * mocking required.
 */
public final class TenantSlugExtractor {

    private TenantSlugExtractor() {}

    public static Optional<String> extract(String host, String baseDomain) {
        if (host == null || host.isBlank() || baseDomain == null || baseDomain.isBlank()) {
            return Optional.empty();
        }

        String normalizedHost = host.trim().toLowerCase(Locale.ROOT);
        String normalizedBaseDomain = baseDomain.trim().toLowerCase(Locale.ROOT);

        if (normalizedHost.equals(normalizedBaseDomain)) {
            return Optional.empty();
        }

        String suffix = "." + normalizedBaseDomain;
        if (!normalizedHost.endsWith(suffix)) {
            return Optional.empty();
        }

        String prefix = normalizedHost.substring(0, normalizedHost.length() - suffix.length());
        if (prefix.isBlank() || prefix.contains(".")) {
            // A nested subdomain (e.g. "a.b.localhost") isn't a supported tenant slug shape -
            // TenantSlug only ever allows a single label - so it's treated as unresolved rather
            // than passed down as an invalid slug value.
            return Optional.empty();
        }

        return Optional.of(prefix);
    }
}
