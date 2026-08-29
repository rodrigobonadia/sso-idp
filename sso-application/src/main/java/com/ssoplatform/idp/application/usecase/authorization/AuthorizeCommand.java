package com.ssoplatform.idp.application.usecase.authorization;

import java.util.UUID;

/**
 * Input to {@link AuthorizeUseCase}: the raw {@code GET /authorize} query parameters (RFC 6749
 * §4.1.1, plus PKCE per RFC 7636 §4.3, plus the optional OIDC {@code nonce} per OpenID Connect
 * Core 1.0 §3.1.2.1) alongside the tenant and the already-authenticated user, as resolved by the
 * web layer before this use case ever runs.
 *
 * <p>Every {@code String} field here is intentionally UNVALIDATED raw input - all shape/business
 * validation (client_id format, redirect_uri format/registration, supported scopes, PKCE method)
 * happens inside {@link AuthorizeUseCase#execute}, not here, so that every failure path is
 * reported through the exception types that class's Javadoc documents. {@link #nonce} is the one
 * exception: it is never validated at all, only carried through unchanged onto the issued {@link
 * com.ssoplatform.idp.domain.authorization.AuthorizationCode} - see that entity's Javadoc for why.
 */
public record AuthorizeCommand(
        UUID tenantId,
        UUID userId,
        String rawClientId,
        String redirectUri,
        String responseType,
        String scope,
        String state,
        String codeChallenge,
        String codeChallengeMethod,
        String nonce) {}
