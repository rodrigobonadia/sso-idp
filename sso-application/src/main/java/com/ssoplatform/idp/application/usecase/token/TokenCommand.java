package com.ssoplatform.idp.application.usecase.token;

import java.util.UUID;

/**
 * Input to {@link TokenUseCase}: the raw {@code POST /token} form parameters for any grant it
 * supports - {@code authorization_code} (RFC 6749 section 4.1.3, plus PKCE per RFC 7636 section
 * 4.5), {@code refresh_token} (RFC 6749 section 6), {@code client_credentials} (RFC 6749 section
 * 4.4, with the {@code resource} parameter per RFC 8707), or {@code
 * urn:ietf:params:oauth:grant-type:device_code} (RFC 8628 section 3.4) - together with the client
 * credentials presented via HTTP Basic authentication (RFC 6749 section 2.3.1 - the only client
 * authentication method this platform accepts for a CONFIDENTIAL client, see {@code
 * architecture_decisions.md}) and the tenant/issuer resolved by the web layer before this use case
 * ever runs.
 *
 * <p>Every {@code String} field is intentionally UNVALIDATED raw input, exactly like {@link
 * com.ssoplatform.idp.application.usecase.authorization.AuthorizeCommand} - all shape/business
 * validation happens inside {@link TokenUseCase#execute}, so every failure path is reported
 * through {@link com.ssoplatform.idp.application.exception.OAuthTokenException}. {@link #code},
 * {@link #redirectUri}, and {@link #codeVerifier} are only meaningful for the {@code
 * authorization_code} grant; {@link #refreshToken} is only meaningful for the {@code
 * refresh_token} grant; {@link #resource} and {@link #scope} are only meaningful for the {@code
 * client_credentials} grant; {@link #deviceCode} is only meaningful for the device code grant -
 * {@link TokenUseCase} reads only the fields relevant to {@link #grantType}, and never validates
 * the others as a side effect of dispatching on it.
 *
 * <p>{@link #basicAuthClientId} and {@link #basicAuthClientSecret} are {@code null} when the
 * request carried no {@code Authorization} header at all, or one that could not be parsed as HTTP
 * Basic - {@link TokenUseCase} treats both cases identically ({@code invalid_client}), never
 * distinguishing "missing" from "malformed" in its response, the same enumeration-safety reasoning
 * {@code OAuthClientNotFoundException} already documents for {@code /authorize}.
 *
 * <p>{@link #clientId} is a SEPARATE field from {@link #basicAuthClientId}, added in the Device
 * Authorization Grant phase: a PUBLIC client (see {@code OAuthClient#isPublic()}) has no secret to
 * present via HTTP Basic at all, so it identifies itself with a plain {@code client_id} body
 * parameter instead - exactly mirroring {@code RequestDeviceAuthorizationCommand#rawClientId}. It
 * is only ever consulted for the device code grant, and only when {@link #basicAuthClientId} is
 * absent - see {@code TokenUseCase#authenticateClient}'s Javadoc for the exact precedence rule.
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
        String refreshToken,
        String resource,
        String scope,
        String deviceCode,
        String clientId,
        String basicAuthClientId,
        String basicAuthClientSecret) {}
