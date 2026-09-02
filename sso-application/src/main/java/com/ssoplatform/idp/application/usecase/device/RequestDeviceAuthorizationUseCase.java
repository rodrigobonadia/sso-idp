package com.ssoplatform.idp.application.usecase.device;

import com.ssoplatform.idp.application.exception.OAuthDeviceAuthorizationException;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.InvalidClientIdException;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Handles a {@code POST /device_authorization} request (RFC 8628 §3.1): issues a fresh, {@code
 * PENDING} {@link DeviceCode} for an input-constrained device (a smart TV, a CLI tool) to poll
 * {@code /token} with, together with the short {@code user_code} a human enters at {@link
 * #verificationUri} on a separate, browser-capable device to approve or deny it.
 *
 * <p>Per RFC 8628 §3.1, "the client authentication requirements of Section 3.2.1 of [RFC6749]
 * apply" to this endpoint exactly like they do to {@code /token} - so {@link #authenticateClient}
 * mirrors {@code TokenUseCase#authenticateClient}'s HTTP Basic check for a <b>confidential</b>
 * client, but additionally accepts a <b>public</b> client (see {@code OAuthClient#isPublic()})
 * identifying itself with nothing more than the body's {@code client_id} - the genuine real-world
 * case this grant exists for. A confidential client that omits Basic credentials, or a public
 * client that presents them, is rejected as {@code invalid_client}: exactly one authentication
 * shape is valid for a given client's type, never both.
 *
 * <p>Scope handling mirrors {@code AuthorizeUseCase} exactly: {@code scope} must be present and
 * non-blank, and every requested scope must be one of both {@link OAuthClient#SUPPORTED_SCOPES}
 * and this specific client's {@link OAuthClient#supportsScope(String)} - there is no "default to
 * every allowed scope when omitted" behavior, for the same reason {@code AuthorizeUseCase} has
 * none.
 *
 * <p>{@link #generateUniqueUserCode} regenerates on a collision against ANY existing {@link
 * DeviceCode} row - not only currently-pending ones - trading a theoretically-unnecessary retry
 * (a collision against a long-expired code) for the simplicity of never having to reason about
 * whether an old row's {@code user_code} might still be looked up ambiguously by the verification
 * page. Collisions are vanishingly rare in practice (the alphabet and length give roughly 10^12
 * possible codes - see {@link UserCode}'s Javadoc), so this never meaningfully affects latency.
 */
public class RequestDeviceAuthorizationUseCase {

    /** RFC 8628 recommends a "reasonable" expiration; 10 minutes is the market-standard default
     * (mirrored by, e.g., GitHub's and Google's device flows). */
    static final Duration DEVICE_CODE_VALIDITY = Duration.ofSeconds(600);

    /** RFC 8628 §3.5's minimum recommended polling interval. */
    static final long POLL_INTERVAL_SECONDS = 5;

    private static final int MAX_USER_CODE_GENERATION_ATTEMPTS = 5;

    private final OAuthClientRepository oauthClientRepository;
    private final ClientSecretHasher clientSecretHasher;
    private final DeviceCodeRepository deviceCodeRepository;
    private final VerificationTokenHasher verificationTokenHasher;

    public RequestDeviceAuthorizationUseCase(
            OAuthClientRepository oauthClientRepository,
            ClientSecretHasher clientSecretHasher,
            DeviceCodeRepository deviceCodeRepository,
            VerificationTokenHasher verificationTokenHasher) {
        this.oauthClientRepository =
                Objects.requireNonNull(oauthClientRepository, "oauthClientRepository must not be null");
        this.clientSecretHasher = Objects.requireNonNull(clientSecretHasher, "clientSecretHasher must not be null");
        this.deviceCodeRepository =
                Objects.requireNonNull(deviceCodeRepository, "deviceCodeRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
    }

    public RequestDeviceAuthorizationResult execute(RequestDeviceAuthorizationCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());

        OAuthClient client = authenticateClient(command, tenantId);

        Set<String> requestedScopes = parseScopes(command.scope());
        if (requestedScopes.isEmpty()) {
            throw new OAuthDeviceAuthorizationException("invalid_request", "At least one scope must be requested");
        }
        for (String scope : requestedScopes) {
            if (!OAuthClient.SUPPORTED_SCOPES.contains(scope) || !client.supportsScope(scope)) {
                throw new OAuthDeviceAuthorizationException(
                        "invalid_scope", "Scope '" + scope + "' is not permitted for this client");
            }
        }

        Instant now = Instant.now();
        RawVerificationToken rawDeviceCode = RawVerificationToken.generate();
        TokenHash deviceCodeHash = verificationTokenHasher.hash(rawDeviceCode);
        UserCode userCode = generateUniqueUserCode();

        DeviceCode deviceCode = DeviceCode.request(
                tenantId, client.id(), deviceCodeHash, userCode, requestedScopes, now, DEVICE_CODE_VALIDITY);
        deviceCodeRepository.save(deviceCode);

        String verificationUriComplete = command.verificationUri() + "?user_code="
                + URLEncoder.encode(userCode.formatted(), StandardCharsets.UTF_8);

        return new RequestDeviceAuthorizationResult(
                rawDeviceCode.value(),
                userCode.formatted(),
                command.verificationUri(),
                verificationUriComplete,
                DEVICE_CODE_VALIDITY.toSeconds(),
                POLL_INTERVAL_SECONDS);
    }

    /**
     * Authenticates the requesting client, accepting exactly one of two shapes: HTTP Basic
     * credentials (for a confidential client) or a bare {@code client_id} form field (for a public
     * client) - never both, never neither. See the class Javadoc for why both are legitimate here,
     * unlike every other grant this platform implements.
     */
    private OAuthClient authenticateClient(RequestDeviceAuthorizationCommand command, TenantId tenantId) {
        boolean hasBasicAuth = !isBlank(command.basicAuthClientId()) && !isBlank(command.basicAuthClientSecret());
        if (hasBasicAuth) {
            return authenticateConfidentialClient(command, tenantId);
        }
        return authenticatePublicClient(command, tenantId);
    }

    private OAuthClient authenticateConfidentialClient(RequestDeviceAuthorizationCommand command, TenantId tenantId) {
        OAuthClient client = resolveClient(command.basicAuthClientId(), tenantId);
        if (client.isPublic()) {
            throw new OAuthDeviceAuthorizationException(
                    "invalid_client", "This client is public and must not present a client secret");
        }
        if (!clientSecretHasher.matches(command.basicAuthClientSecret(), client.clientSecretHash())) {
            throw new OAuthDeviceAuthorizationException("invalid_client", "Client authentication failed");
        }
        return requireUsableAndAuthorized(client);
    }

    private OAuthClient authenticatePublicClient(RequestDeviceAuthorizationCommand command, TenantId tenantId) {
        if (isBlank(command.rawClientId())) {
            throw new OAuthDeviceAuthorizationException("invalid_client", "Client authentication is required");
        }
        OAuthClient client = resolveClient(command.rawClientId(), tenantId);
        if (client.isConfidential()) {
            throw new OAuthDeviceAuthorizationException(
                    "invalid_client", "This client is confidential and must authenticate with its client secret");
        }
        return requireUsableAndAuthorized(client);
    }

    private OAuthClient resolveClient(String rawClientId, TenantId tenantId) {
        ClientId clientId;
        try {
            clientId = ClientId.of(rawClientId);
        } catch (InvalidClientIdException ex) {
            throw new OAuthDeviceAuthorizationException("invalid_client", "Client authentication failed");
        }
        return oauthClientRepository
                .findByClientId(clientId)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(() -> new OAuthDeviceAuthorizationException("invalid_client", "Client authentication failed"));
    }

    private OAuthClient requireUsableAndAuthorized(OAuthClient client) {
        if (!client.isUsable()) {
            throw new OAuthDeviceAuthorizationException("unauthorized_client", "The client is not currently active");
        }
        if (!client.supportsGrantType(GrantType.DEVICE_CODE)) {
            throw new OAuthDeviceAuthorizationException(
                    "unauthorized_client", "The client is not authorized for the device_code grant");
        }
        return client;
    }

    private UserCode generateUniqueUserCode() {
        for (int attempt = 0; attempt < MAX_USER_CODE_GENERATION_ATTEMPTS; attempt++) {
            UserCode candidate = UserCode.generate();
            if (deviceCodeRepository.findByUserCode(candidate).isEmpty()) {
                return candidate;
            }
        }
        throw new IllegalStateException(
                "Unable to generate a unique user code after " + MAX_USER_CODE_GENERATION_ATTEMPTS + " attempts");
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
