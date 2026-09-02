package com.ssoplatform.idp.application.usecase.token;

import com.ssoplatform.idp.application.exception.OAuthTokenException;
import com.ssoplatform.idp.application.port.out.AuthorizationCodeRepository;
import com.ssoplatform.idp.application.port.out.ClientResourceAuthorizationRepository;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.CodeVerifierValidator;
import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.application.port.out.JwtSigner;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.PrivateKeyEncryptor;
import com.ssoplatform.idp.application.port.out.RefreshTokenRepository;
import com.ssoplatform.idp.application.port.out.ResourceRepository;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.DeviceCodeStatus;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.InvalidClientIdException;
import com.ssoplatform.idp.domain.oauth.InvalidRedirectUriException;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenFamilyId;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenReusedException;
import com.ssoplatform.idp.domain.resource.ClientResourceAuthorization;
import com.ssoplatform.idp.domain.resource.InvalidResourceIdentifierException;
import com.ssoplatform.idp.domain.resource.Resource;
import com.ssoplatform.idp.domain.resource.ResourceIdentifier;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.InvalidVerificationTokenException;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Handles a {@code POST /token} request for every grant this platform implements:
 *
 * <ul>
 *   <li>{@code authorization_code} (RFC 6749 §4.1.3), the redemption half of the flow {@code
 *       AuthorizeUseCase} begins - see {@link #executeAuthorizationCodeGrant}.
 *   <li>{@code refresh_token} (RFC 6749 §6), which rotates a previously-issued {@link
 *       RefreshToken} forward one step in its family - see {@link #executeRefreshTokenGrant}.
 *   <li>{@code client_credentials} (RFC 6749 §4.4), a machine-to-machine grant with no resource
 *       owner/user behind it at all - see {@link #executeClientCredentialsGrant}.
 *   <li>{@code urn:ietf:params:oauth:grant-type:device_code} (RFC 8628 §3.4), redeemed by an
 *       input-constrained device repeatedly polling this endpoint while a human approves it
 *       elsewhere - see {@link #executeDeviceCodeGrant}.
 * </ul>
 *
 * On success, the {@code authorization_code} and {@code refresh_token} grants issue a freshly
 * signed access token (JWT, RFC 9068 claim shape) and, when the relevant scopes include {@code
 * openid}, an ID token (OpenID Connect Core 1.0 §2) - both signed with the tenant's current {@code
 * SigningKey} via {@link JwtSigner}, exactly like {@code JwksController} publishes that same key's
 * public half. The {@code authorization_code} grant additionally issues a brand-new refresh token
 * - starting a fresh rotation family (see {@link RefreshToken#issueFirst}) - whenever the redeemed
 * code carried the {@code offline_access} scope AND the client is authorized for the {@code
 * refresh_token} grant; the {@code refresh_token} grant always issues one (continuing the family -
 * see {@link RefreshToken#continueFamily}), since a successful rotation is exactly what replaces
 * the token just consumed.
 *
 * <p>The {@code client_credentials} grant never issues an ID token (there is no end-user to
 * authenticate - OpenID Connect Core does not define ID Tokens for this grant) and never issues a
 * refresh token (the client always holds its own credentials, so it can simply request a brand
 * new access token the same way instead of rotating one). Its access token's {@code sub} claim is
 * the client's own {@code client_id} - there is no {@link UserId} to use - and its {@code aud}
 * claim is the target {@link Resource}'s {@link
 * com.ssoplatform.idp.domain.resource.ResourceIdentifier}, resolved from the required {@code
 * resource} request parameter (RFC 8707 "Resource Indicators for OAuth 2.0") rather than always
 * being the client itself the way the other two grants' access tokens are. See {@link
 * #executeClientCredentialsGrant} for the full authorization chain: the client must both support
 * the {@code CLIENT_CREDENTIALS} grant type AND hold a {@link ClientResourceAuthorization} for the
 * requested resource, and the requested (or, if omitted, every granted) scope must be a subset of
 * that authorization's {@link ClientResourceAuthorization#grantedScopes()} - which is itself
 * defensively re-checked against the resource's OWN current scope catalog ({@link
 * Resource#supportsScope}) in case the two have drifted apart since the authorization was granted.
 *
 * <p>Validation runs in a fixed order, and - unlike {@code AuthorizeUseCase} - EVERY failure from
 * every step throws {@link OAuthTokenException}: RFC 6749 §5.2 never redirects a token error back
 * anywhere, so there is no "before/after a trusted redirect target" split to preserve here.
 *
 * <p>For the {@code authorization_code} grant:
 *
 * <ol>
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
 *
 * <p>For the {@code refresh_token} grant, presenting a token that has already been rotated or
 * revoked is treated as a theft signal (see {@link RefreshTokenReusedException}) rather than an
 * ordinary error: {@link #executeRefreshTokenGrant} responds by revoking every token that shares
 * that family (see {@link #revokeEntireFamily}), forcing the resource owner to re-authenticate
 * from scratch, and only then reports {@code invalid_grant} - never anything more specific, for
 * the same enumeration-safety reason RFC 6749 §5.2 errors never distinguish sub-cases elsewhere in
 * this class.
 *
 * <p>For the {@code client_credentials} grant, every one of "the {@code resource} does not parse
 * as a URI", "no resource is registered for it in this tenant", "the resource is administratively
 * disabled", and "the client holds no {@link ClientResourceAuthorization} for it" is collapsed into
 * the single RFC 8707 error value {@code invalid_target} - the same enumeration-safety reasoning
 * as {@code invalid_grant} above, so a caller probing for valid resource identifiers learns
 * nothing from the response.
 */
public class TokenUseCase {

    static final Duration ACCESS_TOKEN_VALIDITY = Duration.ofMinutes(15);
    static final Duration ID_TOKEN_VALIDITY = Duration.ofMinutes(15);

    /** Fixed absolute validity of an entire refresh token rotation family (see {@code
     * RefreshToken}'s Javadoc) - never extended or "renewed" by rotation. */
    static final Duration REFRESH_TOKEN_FAMILY_VALIDITY = Duration.ofDays(30);

    private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String GRANT_TYPE_DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code";
    private static final String OPENID_SCOPE = "openid";
    private static final String OFFLINE_ACCESS_SCOPE = "offline_access";

    /** Mirrors {@code RequestDeviceAuthorizationUseCase#POLL_INTERVAL_SECONDS} - the same fixed
     * interval a device authorization response advertises is the one a poll is judged against. */
    static final Duration DEVICE_CODE_POLL_INTERVAL = Duration.ofSeconds(5);

    private final OAuthClientRepository oauthClientRepository;
    private final ClientSecretHasher clientSecretHasher;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final ResourceRepository resourceRepository;
    private final ClientResourceAuthorizationRepository clientResourceAuthorizationRepository;
    private final DeviceCodeRepository deviceCodeRepository;
    private final VerificationTokenHasher verificationTokenHasher;
    private final CodeVerifierValidator codeVerifierValidator;
    private final SigningKeyRepository signingKeyRepository;
    private final PrivateKeyEncryptor privateKeyEncryptor;
    private final JwtSigner jwtSigner;

    public TokenUseCase(
            OAuthClientRepository oauthClientRepository,
            ClientSecretHasher clientSecretHasher,
            AuthorizationCodeRepository authorizationCodeRepository,
            RefreshTokenRepository refreshTokenRepository,
            ResourceRepository resourceRepository,
            ClientResourceAuthorizationRepository clientResourceAuthorizationRepository,
            DeviceCodeRepository deviceCodeRepository,
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
        this.refreshTokenRepository =
                Objects.requireNonNull(refreshTokenRepository, "refreshTokenRepository must not be null");
        this.resourceRepository = Objects.requireNonNull(resourceRepository, "resourceRepository must not be null");
        this.clientResourceAuthorizationRepository = Objects.requireNonNull(
                clientResourceAuthorizationRepository, "clientResourceAuthorizationRepository must not be null");
        this.deviceCodeRepository = Objects.requireNonNull(deviceCodeRepository, "deviceCodeRepository must not be null");
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

        if (GRANT_TYPE_AUTHORIZATION_CODE.equals(command.grantType())) {
            return executeAuthorizationCodeGrant(command, tenantId);
        }
        if (GRANT_TYPE_REFRESH_TOKEN.equals(command.grantType())) {
            return executeRefreshTokenGrant(command, tenantId);
        }
        if (GRANT_TYPE_CLIENT_CREDENTIALS.equals(command.grantType())) {
            return executeClientCredentialsGrant(command, tenantId);
        }
        if (GRANT_TYPE_DEVICE_CODE.equals(command.grantType())) {
            return executeDeviceCodeGrant(command, tenantId);
        }
        throw new OAuthTokenException(
                "unsupported_grant_type",
                "Only grant_type=authorization_code, grant_type=refresh_token, "
                        + "grant_type=client_credentials or grant_type=" + GRANT_TYPE_DEVICE_CODE + " is supported");
    }

    private TokenResult executeAuthorizationCodeGrant(TokenCommand command, TenantId tenantId) {
        OAuthClient client = authenticateClient(command, tenantId, GrantType.AUTHORIZATION_CODE);

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

        SigningKey signingKey = currentSigningKey(tenantId);
        byte[] privateKeyDer = privateKeyEncryptor.decrypt(signingKey.encryptedPrivateKey());

        String accessToken = buildAccessToken(
                command.issuer(),
                authorizationCode.userId().value().toString(),
                client.clientId().value(),
                client.clientId().value(),
                authorizationCode.scopes(),
                signingKey,
                privateKeyDer,
                now);

        String idToken = null;
        if (authorizationCode.scopes().contains(OPENID_SCOPE)) {
            idToken = buildIdToken(
                    command.issuer(),
                    client,
                    authorizationCode.userId(),
                    signingKey,
                    privateKeyDer,
                    now,
                    authorizationCode.nonce());
        }

        String rawRefreshToken = null;
        if (authorizationCode.scopes().contains(OFFLINE_ACCESS_SCOPE)
                && client.supportsGrantType(GrantType.REFRESH_TOKEN)) {
            RawVerificationToken rawToken = RawVerificationToken.generate();
            TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
            RefreshToken refreshToken = RefreshToken.issueFirst(
                    tenantId,
                    client.id(),
                    authorizationCode.userId(),
                    tokenHash,
                    authorizationCode.scopes(),
                    now,
                    REFRESH_TOKEN_FAMILY_VALIDITY);
            refreshTokenRepository.save(refreshToken);
            rawRefreshToken = rawToken.value();
        }

        return new TokenResult(accessToken, ACCESS_TOKEN_VALIDITY.toSeconds(), idToken, rawRefreshToken);
    }

    private TokenResult executeRefreshTokenGrant(TokenCommand command, TenantId tenantId) {
        OAuthClient client = authenticateClient(command, tenantId, GrantType.REFRESH_TOKEN);

        if (isBlank(command.refreshToken())) {
            throw new OAuthTokenException("invalid_request", "refresh_token must not be blank");
        }

        TokenHash tokenHash;
        try {
            tokenHash = verificationTokenHasher.hash(RawVerificationToken.of(command.refreshToken()));
        } catch (InvalidVerificationTokenException ex) {
            throw new OAuthTokenException("invalid_grant", "The refresh token is invalid");
        }

        RefreshToken refreshToken = refreshTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() -> new OAuthTokenException("invalid_grant", "The refresh token is invalid"));

        if (!refreshToken.tenantId().equals(tenantId) || !refreshToken.oauthClientId().equals(client.id())) {
            throw new OAuthTokenException("invalid_grant", "The refresh token was not issued to this client");
        }

        Instant now = Instant.now();
        try {
            refreshToken.rotate(now);
        } catch (RefreshTokenReusedException ex) {
            revokeEntireFamily(refreshToken.familyId());
            throw new OAuthTokenException(
                    "invalid_grant", "The refresh token has already been used; the session has been revoked");
        } catch (VerificationTokenExpiredException ex) {
            throw new OAuthTokenException("invalid_grant", "The refresh token has expired");
        }
        refreshTokenRepository.save(refreshToken);

        RawVerificationToken rawNextRefreshToken = RawVerificationToken.generate();
        TokenHash nextTokenHash = verificationTokenHasher.hash(rawNextRefreshToken);
        RefreshToken nextRefreshToken = RefreshToken.continueFamily(refreshToken, nextTokenHash, now);
        refreshTokenRepository.save(nextRefreshToken);

        SigningKey signingKey = currentSigningKey(tenantId);
        byte[] privateKeyDer = privateKeyEncryptor.decrypt(signingKey.encryptedPrivateKey());

        String accessToken = buildAccessToken(
                command.issuer(),
                refreshToken.userId().value().toString(),
                client.clientId().value(),
                client.clientId().value(),
                refreshToken.scopes(),
                signingKey,
                privateKeyDer,
                now);

        String idToken = null;
        if (refreshToken.scopes().contains(OPENID_SCOPE)) {
            // OpenID Connect Core 1.0 section 12.2: an ID Token issued from a refresh MUST NOT
            // carry a nonce claim, unlike the ID Token issued by the original authorization_code
            // redemption.
            idToken = buildIdToken(command.issuer(), client, refreshToken.userId(), signingKey, privateKeyDer, now, null);
        }

        return new TokenResult(accessToken, ACCESS_TOKEN_VALIDITY.toSeconds(), idToken, rawNextRefreshToken.value());
    }

    private TokenResult executeClientCredentialsGrant(TokenCommand command, TenantId tenantId) {
        OAuthClient client = authenticateClient(command, tenantId, GrantType.CLIENT_CREDENTIALS);

        if (isBlank(command.resource())) {
            throw new OAuthTokenException("invalid_request", "resource must not be blank");
        }

        ResourceIdentifier resourceIdentifier;
        try {
            resourceIdentifier = ResourceIdentifier.of(command.resource());
        } catch (InvalidResourceIdentifierException ex) {
            throw new OAuthTokenException("invalid_target", "The resource parameter is invalid");
        }

        Resource resource = resourceRepository
                .findByTenantIdAndIdentifier(tenantId, resourceIdentifier)
                .filter(Resource::isUsable)
                .orElseThrow(() -> new OAuthTokenException(
                        "invalid_target", "The requested resource is unknown or is not currently usable"));

        ClientResourceAuthorization authorization = clientResourceAuthorizationRepository
                .findByOAuthClientIdAndResourceId(client.id(), resource.id())
                .orElseThrow(() -> new OAuthTokenException(
                        "invalid_target", "The client is not authorized to request tokens for this resource"));

        // Defense in depth: only scopes the resource STILL defines count as grantable, in case the
        // resource's own catalog and this authorization's granted-scopes snapshot have drifted
        // apart since the authorization was created - see the class Javadoc.
        Set<String> grantableScopes = authorization.grantedScopes().stream()
                .filter(resource::supportsScope)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        Set<String> issuedScopes;
        Set<String> requestedScopes = parseScopes(command.scope());
        if (requestedScopes.isEmpty()) {
            issuedScopes = grantableScopes;
        } else {
            for (String scope : requestedScopes) {
                if (!grantableScopes.contains(scope)) {
                    throw new OAuthTokenException(
                            "invalid_scope",
                            "Scope '" + scope + "' is not granted to this client for this resource");
                }
            }
            issuedScopes = requestedScopes;
        }
        if (issuedScopes.isEmpty()) {
            throw new OAuthTokenException(
                    "invalid_scope", "This client has no scopes granted for this resource");
        }

        Instant now = Instant.now();
        SigningKey signingKey = currentSigningKey(tenantId);
        byte[] privateKeyDer = privateKeyEncryptor.decrypt(signingKey.encryptedPrivateKey());

        String accessToken = buildAccessToken(
                command.issuer(),
                client.clientId().value(),
                resource.identifier().value(),
                client.clientId().value(),
                issuedScopes,
                signingKey,
                privateKeyDer,
                now);

        return new TokenResult(accessToken, ACCESS_TOKEN_VALIDITY.toSeconds(), null, null);
    }

    /**
     * Handles the {@code urn:ietf:params:oauth:grant-type:device_code} grant (RFC 8628 §3.4): the
     * device polling loop. Every poll first records itself (via {@link DeviceCode#recordPoll}) and
     * is checked against the fixed {@link #DEVICE_CODE_POLL_INTERVAL} BEFORE that recording is
     * considered for the NEXT poll - see {@link DeviceCode#isPolledTooSoon}'s Javadoc for why the
     * order matters - so a client that ignores {@code slow_down} and keeps polling too fast keeps
     * getting {@code slow_down} rather than silently succeeding once enough time has passed
     * relative to some earlier, stale poll.
     *
     * <p>Unlike every other grant in this class, the outcome here is read directly from {@link
     * DeviceCode#status()} rather than caught as a single collapsed exception - see {@code
     * DeviceCodeStatus}'s Javadoc for why a {@code PENDING} vs. {@code DENIED} vs. already-{@code
     * REDEEMED} code must produce three different RFC 8628 error codes rather than one.
     */
    private TokenResult executeDeviceCodeGrant(TokenCommand command, TenantId tenantId) {
        OAuthClient client = authenticateClientForDeviceCodeGrant(command, tenantId);

        if (isBlank(command.deviceCode())) {
            throw new OAuthTokenException("invalid_request", "device_code must not be blank");
        }

        TokenHash deviceCodeHash;
        try {
            deviceCodeHash = verificationTokenHasher.hash(RawVerificationToken.of(command.deviceCode()));
        } catch (InvalidVerificationTokenException ex) {
            throw new OAuthTokenException("invalid_grant", "The device_code is invalid");
        }

        DeviceCode deviceCode = deviceCodeRepository
                .findByDeviceCodeHash(deviceCodeHash)
                .orElseThrow(() -> new OAuthTokenException("invalid_grant", "The device_code is invalid"));

        if (!deviceCode.tenantId().equals(tenantId) || !deviceCode.oauthClientId().equals(client.id())) {
            throw new OAuthTokenException("invalid_grant", "The device_code was not issued to this client");
        }

        Instant now = Instant.now();

        if (deviceCode.isExpired(now)) {
            throw new OAuthTokenException("expired_token", "The device code has expired");
        }

        boolean polledTooSoon = deviceCode.isPolledTooSoon(now, DEVICE_CODE_POLL_INTERVAL);
        deviceCode.recordPoll(now);
        deviceCodeRepository.save(deviceCode);
        if (polledTooSoon) {
            throw new OAuthTokenException("slow_down", "The device is polling faster than the allowed interval");
        }

        if (deviceCode.status() == DeviceCodeStatus.PENDING) {
            throw new OAuthTokenException(
                    "authorization_pending", "The end user has not yet completed the verification step");
        }
        if (deviceCode.status() == DeviceCodeStatus.DENIED) {
            throw new OAuthTokenException("access_denied", "The end user denied this device's authorization request");
        }
        if (deviceCode.status() == DeviceCodeStatus.REDEEMED) {
            throw new OAuthTokenException("invalid_grant", "The device_code has already been used");
        }

        // Only DeviceCodeStatus.APPROVED reaches here.
        deviceCode.redeem(now);
        deviceCodeRepository.save(deviceCode);

        SigningKey signingKey = currentSigningKey(tenantId);
        byte[] privateKeyDer = privateKeyEncryptor.decrypt(signingKey.encryptedPrivateKey());

        String accessToken = buildAccessToken(
                command.issuer(),
                deviceCode.userId().value().toString(),
                client.clientId().value(),
                client.clientId().value(),
                deviceCode.scopes(),
                signingKey,
                privateKeyDer,
                now);

        String idToken = null;
        if (deviceCode.scopes().contains(OPENID_SCOPE)) {
            idToken = buildIdToken(command.issuer(), client, deviceCode.userId(), signingKey, privateKeyDer, now, null);
        }

        String rawRefreshToken = null;
        if (deviceCode.scopes().contains(OFFLINE_ACCESS_SCOPE) && client.supportsGrantType(GrantType.REFRESH_TOKEN)) {
            RawVerificationToken rawToken = RawVerificationToken.generate();
            TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
            RefreshToken refreshToken = RefreshToken.issueFirst(
                    tenantId,
                    client.id(),
                    deviceCode.userId(),
                    tokenHash,
                    deviceCode.scopes(),
                    now,
                    REFRESH_TOKEN_FAMILY_VALIDITY);
            refreshTokenRepository.save(refreshToken);
            rawRefreshToken = rawToken.value();
        }

        return new TokenResult(accessToken, ACCESS_TOKEN_VALIDITY.toSeconds(), idToken, rawRefreshToken);
    }

    /**
     * Authenticates the client for the device code grant, accepting exactly one of two shapes:
     * HTTP Basic credentials (for a confidential client, mirroring {@link #authenticateClient}) or
     * a bare {@link TokenCommand#clientId()} form field (for a public client) - never both, never
     * neither. Kept as its own self-contained method, rather than folded into {@link
     * #authenticateClient}, so that grant's simpler confidential-only contract (and its NPE-unsafe
     * direct call to {@link ClientSecretHasher#matches}) never has to reason about a {@code null}
     * {@link OAuthClient#clientSecretHash()} at all - see {@code
     * RequestDeviceAuthorizationUseCase#authenticateClient}, which this mirrors exactly.
     */
    private OAuthClient authenticateClientForDeviceCodeGrant(TokenCommand command, TenantId tenantId) {
        boolean hasBasicAuth = !isBlank(command.basicAuthClientId()) && !isBlank(command.basicAuthClientSecret());
        if (hasBasicAuth) {
            return authenticateConfidentialDeviceClient(command, tenantId);
        }
        return authenticatePublicDeviceClient(command, tenantId);
    }

    private OAuthClient authenticateConfidentialDeviceClient(TokenCommand command, TenantId tenantId) {
        OAuthClient client = resolveClientForDeviceGrant(command.basicAuthClientId(), tenantId);
        if (client.isPublic()) {
            throw new OAuthTokenException(
                    "invalid_client", "This client is public and must not present a client secret");
        }
        if (!clientSecretHasher.matches(command.basicAuthClientSecret(), client.clientSecretHash())) {
            throw new OAuthTokenException("invalid_client", "Client authentication failed");
        }
        return requireUsableAndAuthorizedForDeviceGrant(client);
    }

    private OAuthClient authenticatePublicDeviceClient(TokenCommand command, TenantId tenantId) {
        if (isBlank(command.clientId())) {
            throw new OAuthTokenException("invalid_client", "Client authentication is required");
        }
        OAuthClient client = resolveClientForDeviceGrant(command.clientId(), tenantId);
        if (client.isConfidential()) {
            throw new OAuthTokenException(
                    "invalid_client", "This client is confidential and must authenticate with its client secret");
        }
        return requireUsableAndAuthorizedForDeviceGrant(client);
    }

    private OAuthClient resolveClientForDeviceGrant(String rawClientId, TenantId tenantId) {
        ClientId clientId;
        try {
            clientId = ClientId.of(rawClientId);
        } catch (InvalidClientIdException ex) {
            throw new OAuthTokenException("invalid_client", "Client authentication failed");
        }
        return oauthClientRepository
                .findByClientId(clientId)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(() -> new OAuthTokenException("invalid_client", "Client authentication failed"));
    }

    private OAuthClient requireUsableAndAuthorizedForDeviceGrant(OAuthClient client) {
        if (!client.isUsable()) {
            throw new OAuthTokenException("unauthorized_client", "The client is not currently active");
        }
        if (!client.supportsGrantType(GrantType.DEVICE_CODE)) {
            throw new OAuthTokenException(
                    "unauthorized_client", "The client is not authorized for the device_code grant");
        }
        return client;
    }

    /** Revokes every token sharing {@code familyId} - the reuse-detection response (see the class
     * Javadoc): a stolen-and-already-rotated refresh token means the whole chain is compromised,
     * not just the one value presented. */
    private void revokeEntireFamily(RefreshTokenFamilyId familyId) {
        for (RefreshToken member : refreshTokenRepository.findAllByFamilyId(familyId)) {
            member.revoke();
            refreshTokenRepository.save(member);
        }
    }

    private SigningKey currentSigningKey(TenantId tenantId) {
        return signingKeyRepository
                .findCurrentByTenantId(tenantId)
                .orElseThrow(() -> new IllegalStateException("No current signing key found for tenant " + tenantId));
    }

    /**
     * Authenticates the client via HTTP Basic. Every failure - missing credentials, a malformed
     * {@code client_id}, an unknown client, a client belonging to a different tenant, or a wrong
     * secret - is reported identically as {@code invalid_client}, mirroring the enumeration-safety
     * reasoning {@code OAuthClientNotFoundException} documents for {@code /authorize}. A client
     * that authenticates successfully but is disabled, or is not authorized for {@code
     * requiredGrantType}, gets the more specific {@code unauthorized_client} instead -
     * authentication itself did succeed in that case, so RFC 6749 §5.2's HTTP 401 (reserved for
     * {@code invalid_client}) does not apply.
     */
    private OAuthClient authenticateClient(TokenCommand command, TenantId tenantId, GrantType requiredGrantType) {
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
        if (!client.supportsGrantType(requiredGrantType)) {
            throw new OAuthTokenException(
                    "unauthorized_client",
                    "The client is not authorized for the " + requiredGrantType.name().toLowerCase() + " grant");
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
            String issuer,
            String subject,
            String audience,
            String clientId,
            Set<String> scopes,
            SigningKey signingKey,
            byte[] privateKeyDer,
            Instant now) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("client_id", clientId);
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plus(ACCESS_TOKEN_VALIDITY).getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("scope", String.join(" ", scopes));
        return jwtSigner.sign(claims, privateKeyDer, signingKey.kid().value());
    }

    private String buildIdToken(
            String issuer,
            OAuthClient client,
            UserId userId,
            SigningKey signingKey,
            byte[] privateKeyDer,
            Instant now,
            String nonce) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", userId.value().toString());
        claims.put("aud", client.clientId().value());
        claims.put("iat", now.getEpochSecond());
        claims.put("exp", now.plus(ID_TOKEN_VALIDITY).getEpochSecond());
        if (nonce != null) {
            claims.put("nonce", nonce);
        }
        return jwtSigner.sign(claims, privateKeyDer, signingKey.kid().value());
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static Set<String> parseScopes(String rawScope) {
        if (rawScope == null || rawScope.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(rawScope.trim().split("\\s+"))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
