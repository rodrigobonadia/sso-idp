package com.ssoplatform.idp.api.web.oidc;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code GET /.well-known/openid-configuration}: the OIDC Discovery document (OpenID Connect
 * Discovery 1.0 §3) for the current tenant. Deliberately {@code permitAll} in {@code
 * SecurityConfig} - it already matches the existing {@code /.well-known/**} rule wired for the
 * JWKS document in Phase 3.2, since a discovery document exists to be fetched by anyone
 * bootstrapping an OIDC client integration, so it can never require authentication.
 *
 * <p>Per-tenant, exactly like {@link JwksController}: the request must resolve to a tenant via
 * its subdomain (see {@code TenantResolutionFilter}), or this endpoint responds with the same
 * {@code TenantRequiredException} (400) every other tenant-scoped endpoint does for a root-domain
 * request.
 *
 * <p>Unlike {@link JwksController}, no application-layer use case backs this endpoint: every
 * field in {@link DiscoveryResponse} is either a static capability constant or a URL built from
 * the same {@code app.tenant.base-domain} / {@code app.mail.link-scheme} / {@code server.port}
 * configuration {@code TokenController} already uses to build its {@code iss} claim - composing a
 * URL from Spring configuration is a web-layer concern, not a business rule (see the Phase 3.4
 * issuer decision (j) in {@code architecture_decisions.md}), so there is nothing here for a
 * framework-free use case to encapsulate.
 *
 * <p>See {@link DiscoveryResponse}'s Javadoc for why unimplemented endpoints (userinfo,
 * revocation, introspection) are omitted entirely rather than advertised ahead of being built.
 */
@RestController
public class DiscoveryController {

    private final TenantContext tenantContext;
    private final String tenantBaseDomain;
    private final String linkScheme;
    private final String serverPort;

    public DiscoveryController(
            TenantContext tenantContext,
            @Value("${app.tenant.base-domain}") String tenantBaseDomain,
            @Value("${app.mail.link-scheme:http}") String linkScheme,
            @Value("${server.port}") String serverPort) {
        this.tenantContext = tenantContext;
        this.tenantBaseDomain = tenantBaseDomain;
        this.linkScheme = linkScheme;
        this.serverPort = serverPort;
    }

    @GetMapping("/.well-known/openid-configuration")
    public DiscoveryResponse discover() {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);
        String issuer = buildIssuer(tenant.slug());
        return new DiscoveryResponse(
                issuer,
                issuer + "/authorize",
                issuer + "/token",
                issuer + "/.well-known/jwks.json",
                List.of("openid", "profile", "email"),
                List.of("code"),
                List.of("authorization_code"),
                List.of("public"),
                List.of("RS256"),
                List.of("client_secret_basic"),
                List.of("S256"));
    }

    private String buildIssuer(String tenantSlug) {
        return "%s://%s.%s:%s".formatted(linkScheme, tenantSlug, tenantBaseDomain, serverPort);
    }
}
