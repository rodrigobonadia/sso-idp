package com.ssoplatform.idp.application.usecase.token;

import com.ssoplatform.idp.application.exception.OAuthTokenException;
import com.ssoplatform.idp.application.port.out.AuthorizationCodeRepository;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.CodeVerifierValidator;
import com.ssoplatform.idp.application.port.out.JwtSigner;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.PrivateKeyEncryptor;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.InvalidClientIdException;
import com.ssoplatform.idp.domain.oauth.InvalidRedirectUriException;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.verification.InvalidVerificationTokenException;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Handles a {@code POST /token} request for the {@code authorization_code} grant (RFC 6749
 * §4.1.3), the redemption half of the flow {@code AuthorizeUseCase} begins. On success, issues a
 * freshly signed access token (JWT, RFC 9068 claim shape) and, when the redeemed code carried the
 * {@code openid} scope, an ID token (OpenID Connect Core 1.0 §2) - both signed with the tenant's
 * current {@code SigningKey} via {@link JwtSigner}, exactly like {@code JwksController} publishes
 * that same key's public half.
 *
 * <p>Validation runs in a fixed order, and - unlike {@code AuthorizeUseCase} - EVERY failure from
 * every step throws {@link OAuthTokenException}: RFC 6749 §5.2 never redirects a token error back
 * anywhere, so there is no "before/after a trusted redirect target" split to preserve here.
 *
 * <ol>
 *   <li><b>grant_type</b> must be {@code authorization_code} - the only grant this platform
 *       implements so far.
 *   <li><b>client authentication</b> (HTTP Basic, the only method this platform accepts) must
 *       succeed against a real, active, correctly-scoped client that is authorized for this grant
 *       type - see {@link #authenticateClient}.
 *   <li><b>code, redirect_uri, code_verifier</b> must all be present.
 *   <li>the presented {@code code} must resolve to a real, unconsumed, unexpired {@link
 *       AuthorizationCode} that was issued to THIS client, for THIS {@code redirect_uri}, and
 *       whose {@code code_challenge} the presented {@code code_verifier} satisfies (via {@link
 *       CodeVerifierValidator}) - every one of these failures is reported as the single RFC value
 *       {@code invalid_grant}, deliberately never distinguishing which sub-check failed, so a
 *       malicious caller learns nothing more than "this grant is not redeemable".
 * </ol>
 *
 * <p>The code is marked consumed (via {@link AuthorizationCode#consume}) only AFTER every other
 * check has already passed - never as a side effect of a failed validation - so a legitimate client
 * that failed one check (e.g. a transient client-side bug in the {@code code_verifier} it sent) can
 * still retry with the same code before it expires.
 */
public class TokenUseCase {

    static final Duration ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(15);
    static final Duration ID_TOKEN_VALIDITY = Duration.ofMinutes(15);

    private static final String SUPPORTED_GRANT_TYPE = "authorization_code";
    private static final String OPENID_SCOPE = "openid";

    private final OAuthClientRepository oauthClientRepository;
    private final ClientSecretHasher clientSecretHasher;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final VerificationTokenHasher verificationTokenHasher;
    private final CodeVerifierValidator codeVerifierValidator;
    private final SigningKeyRepository signingKeyRepository;
    private final PrivateKeyEncryptor privateKeyEncryptor;
    private final JwtSigner jwtSigner;

    public TokenUseCase(
            OAuthClientRepository oauthClientRepository,
            ClientSecretHasher clientSecretHasher,
            AuthorizationCodeRepository authorizationCodeRepository,
            VerificationTokenHasher verificationTokenHasher,
            CodeVerifierValidator codeVerifierValidator,
            SigningKeyRepository signingKeyRepository,
            PrivateKeyEncryptor privateKeyEncryptor,
            JwtSigner jwtSigner) {
        this.oauthClientRepository =
                Objects.requireNonNull(oauthClientRepository, "oauthClientRepository must not be null");
        this.clientSecretHasher = Objects.requireNonNull(clientSecretHasher, "clientSecretHasher must not be null");
        this.authorizationCodeRepository =
                Objects.requireNonNull(authorizationCodeRepository, "authorizationCodeRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
        this.codeVerifierValidator =
                Objects.requireNonNull(codeVerifierValidator, "codeVerifierValidator must not be null");
        this.signingKeyRepository =
                Objects.requireNonNull(signingKeyRepository, "signingKeyRepository must not be null");
        this.privateKeyEncryptor = Objects.requireNonNull(privateKeyEncryptor, "privateKeyEncryptor must not be null");
        this.jwtSigner = Objects.requireNonNull(jwtSigner, "jwtSigner must not be null");
    }

    public TokenResult execute(TokenCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());

        if (!SUPPORTED_GRANT_TYPE.equals(command.grantType())) {
            throw new OAuthTokenException("unsupported_grant_type", "Only grant_type=authorization_code is supported");
        }

        OAuthClient client = authenticateClient(command, tenantId);

        if (isBlank(command.code())) {
            throw new OAuthTokenException("invalid_request", "code must not be blank");
        }
        if (isBlank(command.redirectUri())) {
            throw new OAuthTokenException("invalid_request", "redirect_uri must not be blank");
        }
        if (isBlank(command.codeVerifier())) {
            throw new OAuthTokenException("invalid_request", "code_verifier must not be blank");
        }

        AuthorizationCode authorizationCode = findAndValidateCode(command, tenantId, client);

        Instant now = Instant.now();
        try {
            authorizationCode.consume(now);
        } catch (VerificationTokenAlreadyConsumedException | VerificationTokenExpiredException ex) {
            throw new OAuthTokenException("invalid_grant", "The authorization code has already been used or has expired");
        }
        authorizationCodeRepository.save(authorizationCode);

        SigningKey signingKey = signingKeyRepository
                .findCurrentByTenantId(tenantId)
                .orElseThrow(() -> new IllegalStateException("No current signing key found for tenant " + tenantId));
        byte[] privateKeyDer = privateKeyEncryptor.decrypt(signingKey.encryptedPrivateKey());

        String accessToken = buildAccessToken(command, client, authorizationCode, signingKey, privateKeyDer, now);

        String idToken = null;
        if (authorizationCode.scopes().contains(OPENID_SCOPE)) {
            idToken = buildIdToken(command, client, authorizationCode, signingKey, privateKeyDer, now);
        }

        return new TokenResult(accessToken, ACCESS_TOKEN_VALIDITY.toSeconds(), idToken);
    }

    /**
     * Authenticates the client via HTTP Basic. Every failure - missing credentials, a malformed
     * {@code client_id}, an unknown client, a client belonging to a different tenant, or a wrong
     * secret - is reported identically as {@code invalid_client}, mirroring the enumeration-safety
     * reasoning {@code OAuthClientNotFoundException} documents for {@code /authorize}. A client
     * that authenticates successfully but is disabled, or is not authorized for this grant type,
     * gets the more specific {@code unauthorized_client} instead - authentication itself did
     * succeed in that case, so RFC 6749 §5.2's HTTP 401 (reserved for {@code invalid_client}) does
     * not apply.
     */
    private OAuthClient authenticateClient(TokenCommand command, TenantId tenantId) {
        if (isBlank(command.basicAuthClientId()) || isBlank(command.basicAuthClientSecret())) {
            throw new OAuthTokenException("invalid_client", "Client authentication is required");
        }

        ClientId clientId;
        try {
            clientId = ClientId.of(command.basicAuthClientId());
        } catch (InvalidClientIdException ex) {
            throw new OAuthTokenException("invalid_client", "Client authentication failed");
        }

        OAuthClient client = oauthClientRepository
                .findByClientId(clientId)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(() -> new OAuthTokenException("invalid_client", "Client authentication failed"));

        if (!clientSecretHasher.matches(command.basicAuthClientSecret(), client.clientSecretHash())) {
            throw new OAuthTokenException("invalid_client", "Client authentication failed");
        }

        if (!client.isUsable()) {
            throw new OAuthTokenException("unauthorized_client", "The client is not currently active");
        }
        if (!client.supportsGrantType(GrantType.AUTHORIZATION_CODE)) {
            throw new OAuthTokenException(
                    "unauthorized_client", "The client is not authorized for the authorization_code grant");
        }

        return client;
    }

    /**
     * Looks up the authorization code and checks every ownership/binding invariant EXCEPT the
     * single-use/expiry state, which {@link AuthorizationCode#consume} enforces separately, later
     * - see the class Javadoc for why that ordering matters.
     */
    private AuthorizationCode findAndValidateCode(TokenCommand command, TenantId tenantId, OAuthClient client) {
        TokenHash codeHash;
        try {
            codeHash = verificationTokenHasher.hash(RawVerificationToken.of(command.code()));
        } catch (InvalidVerificationTokenException ex) {
            throw new OAuthTokenException("invalid_grant", "The authorization code is invalid");
        }

        AuthorizationCode authorizationCode = authorizationCodeRepository
                .findByCodeHash(codeHash)
                .orElseThrow(() -> new OAuthTokenException("invalid_grant", "The authorization code is invalid"));

        if (!authorizationCode.tenantId().equals(tenantId) || !authorizationCode.oauthClientId().equals(client.id())) {
            throw new OAuthTokenException("invalid_grant", "The authorization code was not issued to this client");
        }

        RedirectUri redirectUri;
        try {
            redirectUri = RedirectUri.of(command.redirectUri());
        } catch (InvalidRedirectUriException ex) {
            throw new OAuthTokenException(
                    "invalid_grant", "redirect_uri does not match the value used to obtain the code");
        }
        if (!authorizationCode.redirectUri().equals(redirectUri)) {
            throw new OAuthTokenException(
                    "invalid_grant", "redirect_uri does not match the value used to obtain the code");
        }

        if (!codeVerifierValidator.matches(command.codeVerifier(), authorizationCode.codeChallenge())) {
            throw new OAuthTokenException("invalid_grant", "code_verifier does not match the code_challenge");
        }

        return authorizationCode;
    }

    private String buildAccessToken(
            TokenCommand command,
            OAuthClient client,
            AuthorizationCode code,
            SigningKey signingKey,
            byte[] privateKeyDer,
            Instant now) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", command.issuer());
        claims.put("sub", code.userId().value().toString());
        claims.put("aud", client.clientId().value());
        claims.put("client_id", client.clientId().value());
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plus(ACCESS_TOKEN_VALIDITY).getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("scope", String.join(" ", code.scopes()));
        return jwtSigner.sign(claims, privateKeyDer, signingKey.kid().value());
    }

    private String buildIdToken(
            TokenCommand command,
            OAuthClient client,
            AuthorizationCode code,
            SigningKey signingKey,
            byte[] privateKeyDer,
            Instant now) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", command.issuer());
        claims.put("sub", code.userId().value().toString());
        claims.put("aud", client.clientId().value());
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plus(ID_TOKEN_VALIDITY).getEpochSecond());
        if (code.nonce() != null) {
            claims.put("nonce", code.nonce());
        }
        return jwtSigner.sign(claims, privateKeyDer, signingKey.kid().value());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
