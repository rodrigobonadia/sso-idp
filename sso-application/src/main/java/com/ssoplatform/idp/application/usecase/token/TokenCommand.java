package com.ssoplatform.idp.application.usecase.token;

import java.util.UUID;

/**
 * Input to {@link TokenUseCase}: the raw {@code POST /token} form parameters (RFC 6749 §4.1.3,
 * plus PKCE per RFC 7636 §4.5) together with the client credentials presented via HTTP Basic
 * authentication (RFC 6749 §2.3.1 - the only client authentication method this platform accepts,
 * see {@code architecture_decisions.md}) and the tenant/issuer resolved by the web layer before
 * this use case ever runs.
 *
 * <p>Every {@code String} field is intentionally UNVALIDATED raw input, exactly like {@link
 * com.ssoplatform.idp.application.usecase.authorization.AuthorizeCommand} - all shape/business
 * validation happens inside {@link TokenUseCase#execute}, so every failure path is reported
 * through {@link com.ssoplatform.idp.application.exception.OAuthTokenException}.
 *
 * <p>{@link #basicAuthClientId} and {@link #basicAuthClientSecret} are {@code null} when the
 * request carried no {@code Authorization} header at all, or one that could not be parsed as HTTP
 * Basic - {@link TokenUseCase} treats both cases identically ({@code invalid_client}), never
 * distinguishing "missing" from "malformed" in its response, the same enumeration-safety reasoning
 * {@code OAuthClientNotFoundException} already documents for {@code /authorize}.
 *
 * <p>{@link #issuer} is the already-built {@code iss} claim value for this tenant (e.g. {@code
 * http://acme.localhost:8080}), computed by the web layer from the same {@code
 * app.tenant.base-domain} / {@code app.mail.link-scheme} / {@code server.port} configuration
 * {@code MockEmailSenderAdapter} already uses to build tenant-scoped links - passed in as a raw
 * string for the same reason {@code redirectUri} is: building URLs from configuration is a web/
 * infrastructure-layer concern, not a business rule this framework-free use case should own.
 */
public record TokenCommand(
        UUID tenantId,
        String issuer,
        String grantType,
        String code,
        String redirectUri,
        String codeVerifier,
        String basicAuthClientId,
        String basicAuthClientSecret) {}
