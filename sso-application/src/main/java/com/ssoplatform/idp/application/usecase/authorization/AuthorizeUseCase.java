package com.ssoplatform.idp.application.usecase.authorization;

import com.ssoplatform.idp.application.exception.OAuthAuthorizationException;
import com.ssoplatform.idp.application.exception.OAuthClientNotFoundException;
import com.ssoplatform.idp.application.exception.RedirectUriNotRegisteredException;
import com.ssoplatform.idp.application.port.out.AuthorizationCodeRepository;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.authorization.CodeChallenge;
import com.ssoplatform.idp.domain.authorization.InvalidCodeChallengeException;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Handles a {@code GET /authorize} request for the Authorization Code + PKCE grant, assuming the
 * caller is already an authenticated user in the resolved tenant (the web layer is responsible for
 * that - see {@code AuthorizeController}'s Javadoc for the login-and-resume flow that guarantees
 * it). There is no consent screen to render (a Phase 3 scope decision - clients are trusted,
 * first-party-equivalent applications for now), so a valid request is auto-approved and a code is
 * issued immediately.
 *
 * <p>Validation runs in the exact order RFC 6749 §4.1.2.1 requires, because the two halves have
 * fundamentally different failure semantics:
 *
 * <ol>
 *   <li><b>client_id and redirect_uri</b> (steps 1-4 below) must be confirmed valid and registered
 *       BEFORE anything else. A failure here throws {@link OAuthClientNotFoundException}, {@link
 *       RedirectUriNotRegisteredException}, or a domain-level {@code InvalidClientIdException}/
 *       {@code InvalidRedirectUriException} - none of which {@code AuthorizeController} may turn
 *       into a redirect, because there is no confirmed-trustworthy destination to redirect to yet.
 *   <li><b>everything else</b> (steps 5-10) only runs once the redirect target is trusted, so every
 *       failure from here on throws {@link OAuthAuthorizationException} (carrying an RFC-defined
 *       {@code error} code) - {@code AuthorizeController} redirects these back to the client as
 *       {@code redirect_uri?error=...&error_description=...&state=...}.
 * </ol>
 *
 * <p>Only {@code code_challenge_method=S256} is ever accepted - see {@link CodeChallenge}'s Javadoc
 * for why {@code plain} is rejected outright rather than modeled at all.
 */
public class AuthorizeUseCase {

    /** Deliberately short - RFC 6749 recommends a code lifetime "typically ... ten minutes". */
    static final Duration CODE_VALIDITY = Duration.ofMinutes(5);

    private static final String SUPPORTED_RESPONSE_TYPE = "code";
    private static final String SUPPORTED_CODE_CHALLENGE_METHOD = "S256";

    private final OAuthClientRepository oauthClientRepository;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final VerificationTokenHasher verificationTokenHasher;

    public AuthorizeUseCase(
            OAuthClientRepository oauthClientRepository,
            AuthorizationCodeRepository authorizationCodeRepository,
            VerificationTokenHasher verificationTokenHasher) {
        this.oauthClientRepository =
                Objects.requireNonNull(oauthClientRepository, "oauthClientRepository must not be null");
        this.authorizationCodeRepository =
                Objects.requireNonNull(authorizationCodeRepository, "authorizationCodeRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
    }

    public AuthorizeResult execute(AuthorizeCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());

        // Steps 1-2: client_id must parse and resolve to a client of THIS tenant.
        ClientId clientId = ClientId.of(command.rawClientId());
        OAuthClient client = oauthClientRepository
                .findByClientId(clientId)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(OAuthClientNotFoundException::new);

        // Steps 3-4: redirect_uri must parse and be registered for that client.
        RedirectUri redirectUri = RedirectUri.of(command.redirectUri());
        if (!client.isRedirectUriRegistered(redirectUri)) {
            throw new RedirectUriNotRegisteredException();
        }

        // From this point on, redirectUri is trusted - every failure redirects back to it.

        if (!client.isUsable()) {
            throw new OAuthAuthorizationException("unauthorized_client", "The client is not currently active");
        }

        if (!SUPPORTED_RESPONSE_TYPE.equals(command.responseType())) {
            throw new OAuthAuthorizationException(
                    "unsupported_response_type", "Only response_type=code is supported");
        }

        if (!client.supportsGrantType(GrantType.AUTHORIZATION_CODE)) {
            throw new OAuthAuthorizationException(
                    "unauthorized_client", "The client is not authorized for the authorization_code grant");
        }

        Set<String> requestedScopes = parseScopes(command.scope());
        if (requestedScopes.isEmpty()) {
            throw new OAuthAuthorizationException("invalid_request", "At least one scope must be requested");
        }
        for (String scope : requestedScopes) {
            if (!OAuthClient.SUPPORTED_SCOPES.contains(scope) || !client.supportsScope(scope)) {
                throw new OAuthAuthorizationException(
                        "invalid_scope", "Scope '" + scope + "' is not permitted for this client");
            }
        }

        if (!SUPPORTED_CODE_CHALLENGE_METHOD.equals(command.codeChallengeMethod())) {
            throw new OAuthAuthorizationException(
                    "invalid_request", "code_challenge_method must be " + SUPPORTED_CODE_CHALLENGE_METHOD);
        }
        CodeChallenge codeChallenge;
        try {
            codeChallenge = CodeChallenge.of(command.codeChallenge());
        } catch (InvalidCodeChallengeException ex) {
            throw new OAuthAuthorizationException("invalid_request", ex.getMessage());
        }

        UserId userId = UserId.of(command.userId());
        RawVerificationToken rawCode = RawVerificationToken.generate();
        TokenHash codeHash = verificationTokenHasher.hash(rawCode);

        Instant now = Instant.now();
        AuthorizationCode authorizationCode = AuthorizationCode.issue(
                tenantId, client.id(), userId, codeHash, redirectUri, requestedScopes, codeChallenge, now, CODE_VALIDITY);
        authorizationCodeRepository.save(authorizationCode);

        return new AuthorizeResult(rawCode.value(), redirectUri.value(), command.state());
    }

    private static Set<String> parseScopes(String rawScope) {
        if (rawScope == null || rawScope.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(rawScope.trim().split("\\s+"))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
