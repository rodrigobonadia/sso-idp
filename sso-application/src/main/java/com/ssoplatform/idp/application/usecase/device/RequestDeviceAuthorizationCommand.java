package com.ssoplatform.idp.application.usecase.device;

import java.util.UUID;

/**
 * Input to {@link RequestDeviceAuthorizationUseCase}: the raw {@code POST /device_authorization}
 * form parameters (RFC 8628 §3.1) together with the client credentials presented via HTTP Basic
 * (when the client is confidential - see {@link #basicAuthClientId}/{@link
 * #basicAuthClientSecret}) or via the plain {@link #rawClientId} form field (when the client is
 * public - see {@code OAuthClient#isPublic()}), and the tenant/verification URI resolved by the
 * web layer before this use case ever runs.
 *
 * <p>{@link #rawClientId} and {@link #basicAuthClientId} are deliberately two different fields,
 * unlike {@code TokenCommand} before this phase: a confidential client is authenticated
 * exclusively via HTTP Basic (so {@link #rawClientId} is ignored when Basic credentials are
 * present), while a public client has no secret to present at all and so identifies itself only
 * via the body's {@code client_id} - see {@link RequestDeviceAuthorizationUseCase#authenticateClient}
 * for the exact precedence rule.
 *
 * <p>{@link #verificationUri} is the already-built, tenant-scoped absolute URL of the verification
 * page (e.g. {@code http://acme.localhost:8080/device}), computed by the web layer from the same
 * configuration {@code TokenCommand#issuer} is built from - building URLs from configuration is a
 * web/infrastructure-layer concern, not a business rule this framework-free use case should own.
 */
public record RequestDeviceAuthorizationCommand(
        UUID tenantId,
        String verificationUri,
        String rawClientId,
        String scope,
        String basicAuthClientId,
        String basicAuthClientSecret) {}
