package com.ssoplatform.idp.application.usecase.introspection;

import com.ssoplatform.idp.application.exception.OAuthIntrospectionException;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.JwtVerifier;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.RefreshTokenRepository;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.InvalidClientIdException;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.verification.InvalidVerificationTokenException;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Handles a {@code POST /introspect} request (RFC 7662): reports whether a token this platform
 * issued is currently valid, and if so, a subset of its claims.
 *
 * <p>Tries BOTH kinds of token this platform issues that make sense to introspect - a
 * self-contained access token JWT (verified via {@link JwtVerifier}, exactly like {@code
 * GetUserInfoUseCase}) and an opaque {@link RefreshToken} (looked up by hash, exactly like {@code
 * TokenUseCase}'s {@code refresh_token} grant) - since RFC 7662's {@code token_type_hint} is
 * explicitly advisory, not authoritative (§2.1: "the authorization server... SHOULD accommodate
 * the case that it doesn't"). An ID token is deliberately never treated as introspectable here,
 * even though it happens to be signed the same way as an access token: it carries neither a
 * {@code client_id} nor a {@code jti} claim (see {@code TokenUseCase#buildIdToken}), which is
 * exactly the signal used below to tell the two apart. ID tokens are OIDC artifacts consumed once
 * by the client that requested them, not bearer credentials a resource server would ever need to
 * introspect - every real-world IdP draws this same line.
 *
 * <p>EVERY failure - an unknown token, a malformed one, one that has expired/been revoked, or one
 * that belongs to a different client or tenant than the caller authenticated as - is reported
 * identically as {@link IntrospectTokenResult#inactive()} ({@code {"active": false}}), never a
 * distinguishing exception: exactly the enumeration-safety reasoning {@code TokenUseCase}
 * documents for {@code invalid_grant} applies here too, since a scanning attacker must learn
 * nothing more from this endpoint than "this token is not currently valid for you". {@link
 * OAuthIntrospectionException} is reserved for failures that prevent evaluating the request AT
 * ALL - a missing {@code token} parameter, or the calling client's own credentials being wrong.
 */
public class IntrospectTokenUseCase {

    private static final String REFRESH_TOKEN_HINT = "refresh_token";

    private final OAuthClientRepository oauthClientRepository;
    private final ClientSecretHasher clientSecretHasher;
    private final SigningKeyRepository signingKeyRepository;
    private final JwtVerifier jwtVerifier;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenHasher verificationTokenHasher;

    public IntrospectTokenUseCase(
            OAuthClientRepository oauthClientRepository,
            ClientSecretHasher clientSecretHasher,
            SigningKeyRepository signingKeyRepository,
            JwtVerifier jwtVerifier,
            RefreshTokenRepository refreshTokenRepository,
            VerificationTokenHasher verificationTokenHasher) {
        this.oauthClientRepository =
                Objects.requireNonNull(oauthClientRepository, "oauthClientRepository must not be null");
        this.clientSecretHasher = Objects.requireNonNull(clientSecretHasher, "clientSecretHasher must not be null");
        this.signingKeyRepository =
                Objects.requireNonNull(signingKeyRepository, "signingKeyRepository must not be null");
        this.jwtVerifier = Objects.requireNonNull(jwtVerifier, "jwtVerifier must not be null");
        this.refreshTokenRepository =
                Objects.requireNonNull(refreshTokenRepository, "refreshTokenRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
    }

    public IntrospectTokenResult execute(IntrospectTokenCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());
        OAuthClient client = authenticateClient(command, tenantId);

        if (isBlank(command.token())) {
            throw new OAuthIntrospectionException("invalid_request", "token must not be blank");
        }

        if (REFRESH_TOKEN_HINT.equals(command.tokenTypeHint())) {
            Optional<IntrospectTokenResult> asRefreshToken = tryAsRefreshToken(command.token(), tenantId, client);
            if (asRefreshToken.isPresent()) {
                return asRefreshToken.get();
            }
            return tryAsAccessToken(command.token(), tenantId, client).orElseGet(IntrospectTokenResult::inactive);
        }

        Optional<IntrospectTokenResult> asAccessToken = tryAsAccessToken(command.token(), tenantId, client);
        if (asAccessToken.isPresent()) {
            return asAccessToken.get();
        }
        return tryAsRefreshToken(command.token(), tenantId, client).orElseGet(IntrospectTokenResult::inactive);
    }

    private Optional<IntrospectTokenResult> tryAsAccessToken(String token, TenantId tenantId, OAuthClient client) {
        Map<String, Object> claims = jwtVerifier.verify(token, candidateKeys(tenantId)).orElse(null);
        if (claims == null) {
            return Optional.empty();
        }
        Object jti = claims.get("jti");
        Object claimedClientId = claims.get("client_id");
        if (!(jti instanceof String) || !(claimedClientId instanceof String claimedClientIdValue)) {
            // No jti/client_id claim means this JWT is not an access token (e.g. an ID token) -
            // not introspectable via this endpoint, see the class Javadoc.
            return Optional.empty();
        }
        if (!claimedClientIdValue.equals(client.clientId().value())) {
            // Verifies, but was not issued to the client making this request - report inactive
            // rather than leaking that a valid token exists for some OTHER client.
            return Optional.empty();
        }
        return Optional.of(new IntrospectTokenResult(
                true,
                (String) claims.get("scope"),
                claimedClientIdValue,
                "Bearer",
                asLong(claims.get("exp")),
                asLong(claims.get("iat")),
                (String) claims.get("sub"),
                (String) claims.get("aud"),
                (String) claims.get("iss"),
                (String) jti));
    }

    private Optional<IntrospectTokenResult> tryAsRefreshToken(String token, TenantId tenantId, OAuthClient client) {
        TokenHash tokenHash;
        try {
            tokenHash = verificationTokenHasher.hash(RawVerificationToken.of(token));
        } catch (InvalidVerificationTokenException ex) {
            return Optional.empty();
        }

        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash).orElse(null);
        if (refreshToken == null
                || !refreshToken.tenantId().equals(tenantId)
                || !refreshToken.oauthClientId().equals(client.id())) {
            return Optional.empty();
        }
        if (!refreshToken.isActive() || refreshToken.isExpired(Instant.now())) {
            return Optional.empty();
        }

        return Optional.of(new IntrospectTokenResult(
                true,
                String.join(" ", refreshToken.scopes()),
                client.clientId().value(),
                REFRESH_TOKEN_HINT,
                refreshToken.familyExpiresAt().getEpochSecond(),
                refreshToken.createdAt().getEpochSecond(),
                refreshToken.userId().value().toString(),
                null,
                null,
                refreshToken.id().value().toString()));
    }

    private Map<String, byte[]> candidateKeys(TenantId tenantId) {
        Map<String, byte[]> keys = new HashMap<>();
        for (SigningKey signingKey : signingKeyRepository.findAllByTenantId(tenantId)) {
            keys.put(signingKey.kid().value(), Base64.getDecoder().decode(signingKey.publicKey().value()));
        }
        return keys;
    }

    /** Mirrors {@code TokenUseCase#authenticateClient}, minus the grant-type check - introspection
     * is not scoped to any particular grant, only to the client being a real, active, confidential
     * client of THIS tenant. */
    private OAuthClient authenticateClient(IntrospectTokenCommand command, TenantId tenantId) {
        if (isBlank(command.basicAuthClientId()) || isBlank(command.basicAuthClientSecret())) {
            throw new OAuthIntrospectionException("invalid_client", "Client authentication is required");
        }

        ClientId clientId;
        try {
            clientId = ClientId.of(command.basicAuthClientId());
        } catch (InvalidClientIdException ex) {
            throw new OAuthIntrospectionException("invalid_client", "Client authentication failed");
        }

        OAuthClient client = oauthClientRepository
                .findByClientId(clientId)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(() -> new OAuthIntrospectionException("invalid_client", "Client authentication failed"));

        if (client.isPublic() || !clientSecretHasher.matches(command.basicAuthClientSecret(), client.clientSecretHash())) {
            throw new OAuthIntrospectionException("invalid_client", "Client authentication failed");
        }
        if (!client.isUsable()) {
            throw new OAuthIntrospectionException("invalid_client", "Client authentication failed");
        }

        return client;
    }

    private static Long asLong(Object value) {
        return value instanceof Number number ? number.longValue() : null;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
