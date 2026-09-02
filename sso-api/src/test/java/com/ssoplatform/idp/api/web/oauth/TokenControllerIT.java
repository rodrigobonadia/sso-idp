package com.ssoplatform.idp.api.web.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssoplatform.idp.api.web.rest.LoginRequest;
import com.ssoplatform.idp.api.web.rest.RegisterRequest;
import com.ssoplatform.idp.api.web.rest.VerifyEmailRequest;
import com.ssoplatform.idp.application.port.out.ClientResourceAuthorizationRepository;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.ResourceRepository;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyCommand;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyUseCase;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantResult;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.resource.ClientResourceAuthorization;
import com.ssoplatform.idp.domain.resource.Resource;
import com.ssoplatform.idp.domain.resource.ResourceIdentifier;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.notification.MockEmailSenderAdapter;
import jakarta.servlet.http.HttpSession;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises {@code POST /token} end-to-end: real Spring context, real Postgres via Testcontainers,
 * a REAL PKCE {@code code_verifier}/{@code code_challenge} pair, and a real signed JWT whose
 * signature is verified against the tenant's own published JWKS document ({@code GET
 * /.well-known/jwks.json}) - not just structurally inspected - proving the whole
 * authorize-then-redeem round trip actually works with a verifier that has no special knowledge of
 * this codebase, exactly like a real OAuth client would verify it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class TokenControllerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final Pattern TOKEN_PATTERN = Pattern.compile("token=([A-Za-z0-9_-]+)");
    private static final Pattern CODE_PATTERN = Pattern.compile("[?&]code=([A-Za-z0-9_-]+)");
    private static final String REDIRECT_URI = "https://app.example.com/callback";
    private static final String RAW_CLIENT_SECRET = "correct-horse-battery-staple";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

    @Autowired
    private OAuthClientRepository oauthClientRepository;

    @Autowired
    private ClientSecretHasher clientSecretHasher;

    @Autowired
    private ResourceRepository resourceRepository;

    @Autowired
    private ClientResourceAuthorizationRepository clientResourceAuthorizationRepository;

    @Autowired
    private GenerateSigningKeyUseCase generateSigningKeyUseCase;

    @Autowired
    private ObjectMapper objectMapper;

    private ListAppender<ILoggingEvent> mailAppender;
    private Logger mailLogger;

    @BeforeEach
    void setUp() {
        mailLogger = (Logger) LoggerFactory.getLogger(MockEmailSenderAdapter.class);
        mailAppender = new ListAppender<>();
        mailAppender.start();
        mailLogger.addAppender(mailAppender);
    }

    @AfterEach
    void tearDown() {
        mailLogger.detachAppender(mailAppender);
    }

    private record TenantAndClient(String tenantSubdomain, String clientIdValue) {}

    private TenantAndClient provisionTenantClientAndSigningKey(String tenantSlug, String clientIdValue) {
        CreateTenantResult tenant = createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", tenantSlug));
        OAuthClient client = OAuthClient.register(
                TenantId.of(tenant.tenantId()),
                ClientId.of(clientIdValue),
                clientSecretHasher.hash(RAW_CLIENT_SECRET),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI)),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE));
        oauthClientRepository.save(client);
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));
        return new TenantAndClient(tenantSlug + ".localhost", clientIdValue);
    }

    private TenantAndClient provisionOfflineAccessClientAndSigningKey(String tenantSlug, String clientIdValue) {
        CreateTenantResult tenant = createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", tenantSlug));
        OAuthClient client = OAuthClient.register(
                TenantId.of(tenant.tenantId()),
                ClientId.of(clientIdValue),
                clientSecretHasher.hash(RAW_CLIENT_SECRET),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI)),
                Set.of("openid", "profile", "offline_access"),
                Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
        oauthClientRepository.save(client);
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));
        return new TenantAndClient(tenantSlug + ".localhost", clientIdValue);
    }

    private TenantAndClient provisionClientCredentialsClientAndResource(
            String tenantSlug,
            String clientIdValue,
            String resourceIdentifierValue,
            Set<String> resourceScopes,
            Set<String> grantedScopes) {
        CreateTenantResult tenant = createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", tenantSlug));
        OAuthClient client = OAuthClient.register(
                TenantId.of(tenant.tenantId()),
                ClientId.of(clientIdValue),
                clientSecretHasher.hash(RAW_CLIENT_SECRET),
                "Billing Service",
                Set.of(RedirectUri.of(REDIRECT_URI)),
                Set.of("openid"),
                Set.of(GrantType.CLIENT_CREDENTIALS));
        oauthClientRepository.save(client);
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));

        Resource resource = Resource.register(
                TenantId.of(tenant.tenantId()),
                ResourceIdentifier.of(resourceIdentifierValue),
                "Orders API",
                resourceScopes);
        resourceRepository.save(resource);
        if (!grantedScopes.isEmpty()) {
            ClientResourceAuthorization authorization = ClientResourceAuthorization.authorize(
                    TenantId.of(tenant.tenantId()), client.id(), resource.id(), grantedScopes);
            clientResourceAuthorizationRepository.save(authorization);
        }
        return new TenantAndClient(tenantSlug + ".localhost", clientIdValue);
    }

    /** RFC 7636 §4.1: 43-128 unreserved characters, generated the same way a real client would. */
    private static String randomCodeVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String challengeFor(String codeVerifier) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private String obtainAuthorizationCode(String tenantSubdomain, String clientIdValue, String codeChallenge)
            throws Exception {
        return obtainAuthorizationCode(tenantSubdomain, clientIdValue, codeChallenge, "openid profile", null);
    }

    private String obtainAuthorizationCode(
            String tenantSubdomain, String clientIdValue, String codeChallenge, String scope, String nonce)
            throws Exception {
        HttpSession session = registerVerifyAndLogin(
                tenantSubdomain, "token-it-" + System.nanoTime() + "@example.com", "Str0ng!Passw0rd");

        var requestBuilder = get("/authorize")
                .session((MockHttpSession) session)
                .with(request -> {
                    request.setServerName(tenantSubdomain);
                    return request;
                })
                .param("client_id", clientIdValue)
                .param("redirect_uri", REDIRECT_URI)
                .param("response_type", "code")
                .param("scope", scope)
                .param("state", "xyz-state")
                .param("code_challenge", codeChallenge)
                .param("code_challenge_method", "S256");
        if (nonce != null) {
            requestBuilder = requestBuilder.param("nonce", nonce);
        }

        MvcResult result = mockMvc.perform(requestBuilder).andExpect(status().is3xxRedirection()).andReturn();
        String redirectedUrl = result.getResponse().getRedirectedUrl();
        Matcher matcher = CODE_PATTERN.matcher(redirectedUrl);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    @Test
    void redeemsACodeForAnAccessTokenAndAVerifiableSignedIdToken() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-token-happy", "acme-token-happy-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(
                ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier), "openid profile", "my-nonce-1");

        MvcResult result = mockMvc.perform(tokenRequest(ctx, code, codeVerifier))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andReturn();

        Map<String, Object> body =
                objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(body.get("token_type")).isEqualTo("Bearer");
        assertThat(body.get("expires_in")).isEqualTo(900);
        String accessToken = (String) body.get("access_token");
        String idToken = (String) body.get("id_token");
        assertThat(accessToken).isNotBlank();
        assertThat(idToken).isNotBlank();

        RSAPublicKey publicKey = fetchTenantPublicKey(ctx.tenantSubdomain());
        assertThat(verifiesSignature(accessToken, publicKey)).isTrue();
        assertThat(verifiesSignature(idToken, publicKey)).isTrue();
    }

    @Test
    void theIdTokenCarriesTheExpectedClaimsIncludingTheEchoedNonce() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-token-claims", "acme-token-claims-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(
                ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier), "openid profile", "abc-nonce-xyz");

        MvcResult result = mockMvc.perform(tokenRequest(ctx, code, codeVerifier)).andExpect(status().isOk()).andReturn();
        Map<String, Object> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        Map<String, Object> idTokenClaims = decodeJwtPayload((String) body.get("id_token"));

        assertThat(idTokenClaims.get("aud")).isEqualTo(ctx.clientIdValue());
        assertThat(idTokenClaims.get("nonce")).isEqualTo("abc-nonce-xyz");
        assertThat(idTokenClaims.get("sub")).isNotNull();
        assertThat(idTokenClaims.get("iss").toString()).contains(ctx.tenantSubdomain());
    }

    @Test
    void omitsTheIdTokenWhenOpenidScopeWasNotGranted() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-token-noopenid", "acme-token-noopenid-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(
                ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier), "profile", null);

        MvcResult result = mockMvc.perform(tokenRequest(ctx, code, codeVerifier)).andExpect(status().isOk()).andReturn();
        Map<String, Object> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);

        assertThat(body).doesNotContainKey("id_token");
    }

    @Test
    void rejectsRedeemingTheSameCodeTwice() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-token-reuse", "acme-token-reuse-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier));

        mockMvc.perform(tokenRequest(ctx, code, codeVerifier)).andExpect(status().isOk());

        mockMvc.perform(tokenRequest(ctx, code, codeVerifier))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void rejectsAWrongClientSecretWithUnauthorizedAndWwwAuthenticate() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-token-badsecret", "acme-token-badsecret-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier));

        mockMvc.perform(post("/token")
                        .with(request -> {
                            request.setServerName(ctx.tenantSubdomain());
                            return request;
                        })
                        .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(ctx.clientIdValue(), "wrong-secret"))
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", codeVerifier))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic"))
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void rejectsAWrongCodeVerifier() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-token-badverifier", "acme-token-badverifier-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier));

        mockMvc.perform(tokenRequest(ctx, code, "a-completely-different-verifier-value"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void redeemingACodeWithOfflineAccessScopeAlsoReturnsARefreshToken() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-token-offline", "acme-token-offline-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(
                ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier), "openid offline_access", null);

        MvcResult result = mockMvc.perform(tokenRequest(ctx, code, codeVerifier)).andExpect(status().isOk()).andReturn();
        Map<String, Object> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);

        assertThat(body.get("refresh_token")).isNotNull();
        assertThat((String) body.get("refresh_token")).isNotBlank();
    }

    @Test
    void doesNotReturnARefreshTokenWhenOfflineAccessWasNotRequested() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-token-noscope", "acme-token-noscope-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(
                ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier), "openid profile", null);

        MvcResult result = mockMvc.perform(tokenRequest(ctx, code, codeVerifier)).andExpect(status().isOk()).andReturn();
        Map<String, Object> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);

        assertThat(body).doesNotContainKey("refresh_token");
    }

    @Test
    void redeemsARefreshTokenForANewAccessTokenAndRotatesIt() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-token-refresh", "acme-token-refresh-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(
                ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier), "openid offline_access", null);
        MvcResult firstResult =
                mockMvc.perform(tokenRequest(ctx, code, codeVerifier)).andExpect(status().isOk()).andReturn();
        Map<String, Object> firstBody =
                objectMapper.readValue(firstResult.getResponse().getContentAsString(), Map.class);
        String firstRefreshToken = (String) firstBody.get("refresh_token");

        MvcResult secondResult = mockMvc.perform(refreshTokenRequest(ctx, firstRefreshToken))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andReturn();
        Map<String, Object> secondBody =
                objectMapper.readValue(secondResult.getResponse().getContentAsString(), Map.class);

        assertThat(secondBody.get("access_token")).isNotNull();
        assertThat(secondBody.get("id_token")).isNotNull();
        String secondRefreshToken = (String) secondBody.get("refresh_token");
        assertThat(secondRefreshToken).isNotBlank();
        assertThat(secondRefreshToken).isNotEqualTo(firstRefreshToken);

        RSAPublicKey publicKey = fetchTenantPublicKey(ctx.tenantSubdomain());
        assertThat(verifiesSignature((String) secondBody.get("access_token"), publicKey)).isTrue();
    }

    @Test
    void reusingAnAlreadyRotatedRefreshTokenRevokesTheWholeFamilyAndBothTokensStopWorking() throws Exception {
        TenantAndClient ctx =
                provisionOfflineAccessClientAndSigningKey("acme-token-reuse-rt", "acme-token-reuse-rt-client");
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(
                ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier), "openid offline_access", null);
        MvcResult firstResult =
                mockMvc.perform(tokenRequest(ctx, code, codeVerifier)).andExpect(status().isOk()).andReturn();
        String firstRefreshToken =
                (String) objectMapper.readValue(firstResult.getResponse().getContentAsString(), Map.class)
                        .get("refresh_token");

        MvcResult secondResult = mockMvc.perform(refreshTokenRequest(ctx, firstRefreshToken))
                .andExpect(status().isOk())
                .andReturn();
        String secondRefreshToken =
                (String) objectMapper.readValue(secondResult.getResponse().getContentAsString(), Map.class)
                        .get("refresh_token");

        // Presenting the already-rotated first refresh token again is reuse: the whole family -
        // including the currently-valid second token - must be revoked.
        mockMvc.perform(refreshTokenRequest(ctx, firstRefreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));

        mockMvc.perform(refreshTokenRequest(ctx, secondRefreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void rejectsARefreshTokenGrantWhenTheClientIsNotAuthorizedForIt() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-token-rt-unauth", "acme-token-rt-unauth-client");

        mockMvc.perform(refreshTokenRequest(ctx, "irrelevant-value-since-client-check-runs-first"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unauthorized_client"));
    }

    @Test
    void issuesAClientCredentialsAccessTokenWithNoIdTokenOrRefreshToken() throws Exception {
        String resourceIdentifier = "https://api.example.com/orders";
        TenantAndClient ctx = provisionClientCredentialsClientAndResource(
                "acme-cc-happy",
                "acme-cc-happy-client",
                resourceIdentifier,
                Set.of("orders:read", "orders:write"),
                Set.of("orders:read", "orders:write"));

        MvcResult result = mockMvc.perform(clientCredentialsRequest(ctx, resourceIdentifier, null))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
                .andReturn();

        Map<String, Object> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat(body.get("token_type")).isEqualTo("Bearer");
        assertThat(body).doesNotContainKey("id_token");
        assertThat(body).doesNotContainKey("refresh_token");
        String accessToken = (String) body.get("access_token");
        assertThat(accessToken).isNotBlank();

        RSAPublicKey publicKey = fetchTenantPublicKey(ctx.tenantSubdomain());
        assertThat(verifiesSignature(accessToken, publicKey)).isTrue();

        Map<String, Object> claims = decodeJwtPayload(accessToken);
        assertThat(claims.get("sub")).isEqualTo(ctx.clientIdValue());
        assertThat(claims.get("aud")).isEqualTo(resourceIdentifier);
        assertThat(claims.get("client_id")).isEqualTo(ctx.clientIdValue());
    }

    @Test
    void rejectsAClientCredentialsRequestWithNoResourceParameter() throws Exception {
        TenantAndClient ctx = provisionClientCredentialsClientAndResource(
                "acme-cc-noresource",
                "acme-cc-noresource-client",
                "https://api.example.com/orders",
                Set.of("orders:read"),
                Set.of("orders:read"));

        mockMvc.perform(clientCredentialsRequest(ctx, null, null))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void rejectsAClientCredentialsRequestForAnUnknownResource() throws Exception {
        TenantAndClient ctx = provisionClientCredentialsClientAndResource(
                "acme-cc-unknown",
                "acme-cc-unknown-client",
                "https://api.example.com/orders",
                Set.of("orders:read"),
                Set.of("orders:read"));

        mockMvc.perform(clientCredentialsRequest(ctx, "https://api.example.com/no-such-resource", null))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_target"));
    }

    @Test
    void rejectsAClientCredentialsRequestWhenTheClientHasNoAuthorizationForTheResource() throws Exception {
        String resourceIdentifier = "https://api.example.com/orders";
        TenantAndClient ctx = provisionClientCredentialsClientAndResource(
                "acme-cc-noauth",
                "acme-cc-noauth-client",
                resourceIdentifier,
                Set.of("orders:read"),
                Set.of()); // no ClientResourceAuthorization created at all

        mockMvc.perform(clientCredentialsRequest(ctx, resourceIdentifier, null))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_target"));
    }

    @Test
    void rejectsAClientCredentialsRequestForAScopeNotGrantedToThisClient() throws Exception {
        String resourceIdentifier = "https://api.example.com/orders";
        TenantAndClient ctx = provisionClientCredentialsClientAndResource(
                "acme-cc-scope",
                "acme-cc-scope-client",
                resourceIdentifier,
                Set.of("orders:read", "orders:write"),
                Set.of("orders:read"));

        mockMvc.perform(clientCredentialsRequest(ctx, resourceIdentifier, "orders:write"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder clientCredentialsRequest(
            TenantAndClient ctx, String resource, String scope) {
        var builder = post("/token")
                .with(request -> {
                    request.setServerName(ctx.tenantSubdomain());
                    return request;
                })
                .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                .param("grant_type", "client_credentials");
        if (resource != null) {
            builder = builder.param("resource", resource);
        }
        if (scope != null) {
            builder = builder.param("scope", scope);
        }
        return builder;
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder tokenRequest(
            TenantAndClient ctx, String code, String codeVerifier) {
        // Deliberately no .with(csrf()) here - a real OAuth client never has a CSRF token to
        // present (see SecurityConfig's Javadoc for why /token is CSRF-exempt), so this proves
        // the exemption actually works rather than masking it.
        return post("/token")
                .with(request -> {
                    request.setServerName(ctx.tenantSubdomain());
                    return request;
                })
                .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", REDIRECT_URI)
                .param("code_verifier", codeVerifier);
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder refreshTokenRequest(
            TenantAndClient ctx, String refreshToken) {
        return post("/token")
                .with(request -> {
                    request.setServerName(ctx.tenantSubdomain());
                    return request;
                })
                .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken);
    }

    private static String basicAuthHeader(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private RSAPublicKey fetchTenantPublicKey(String tenantSubdomain) throws Exception {
        MvcResult jwksResult = mockMvc.perform(get("/.well-known/jwks.json")
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        }))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, Object> jwks = objectMapper.readValue(jwksResult.getResponse().getContentAsString(), Map.class);
        var keys = (java.util.List<Map<String, Object>>) jwks.get("keys");
        assertThat(keys).isNotEmpty();
        Map<String, Object> jwk = keys.get(0);
        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("n")));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("e")));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    private static boolean verifiesSignature(String jwt, RSAPublicKey publicKey) throws Exception {
        String[] parts = jwt.split("\\.");
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getUrlDecoder().decode(parts[2]));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> decodeJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        return objectMapper.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
    }

    private void registerAndVerify(String tenantSubdomain, String email, String password) throws Exception {
        mockMvc.perform(post("/api/register")
                .with(csrf())
                .with(request -> {
                    request.setServerName(tenantSubdomain);
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RegisterRequest(email, "Jane", "Doe", password))));
        String token = extractTokenFromLastMailLog();
        mockMvc.perform(post("/api/verify-email")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new VerifyEmailRequest(token))));
    }

    private HttpSession registerVerifyAndLogin(String tenantSubdomain, String email, String password) throws Exception {
        registerAndVerify(tenantSubdomain, email, password);

        MvcResult loginResult = mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(email, password))))
                .andExpect(status().isOk())
                .andReturn();
        HttpSession session = loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();
        return session;
    }

    private String extractTokenFromLastMailLog() {
        String message = mailAppender.list.get(mailAppender.list.size() - 1).getFormattedMessage();
        Matcher matcher = TOKEN_PATTERN.matcher(message);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }
}
