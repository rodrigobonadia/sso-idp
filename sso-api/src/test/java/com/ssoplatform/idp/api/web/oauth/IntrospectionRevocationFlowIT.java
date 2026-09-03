package com.ssoplatform.idp.api.web.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyCommand;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyUseCase;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantResult;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.notification.MockEmailSenderAdapter;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
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
 * Exercises {@code POST /introspect} (RFC 7662) and {@code POST /revoke} (RFC 7009) end-to-end:
 * real Spring context, real Postgres via Testcontainers, and real signed tokens obtained from an
 * actual {@code POST /token} authorization_code+offline_access grant - not hand-built JWTs -
 * proving the whole authorize-then-introspect/revoke round trip works exactly as a real resource
 * server or client would exercise it. Every client-authentication and token-shape edge case is
 * already covered exhaustively at the {@code IntrospectTokenUseCase}/{@code RevokeTokenUseCase}
 * unit-test level - this class focuses on what only a real end-to-end run can prove: controller
 * wiring, {@code SecurityConfig} permissions (including the CSRF exemption - no test here ever
 * calls {@code .with(csrf())}), and the real interaction between {@code /revoke} and a subsequent
 * {@code /token} refresh_token grant.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class IntrospectionRevocationFlowIT {

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

    private record IssuedTokens(String accessToken, String refreshToken) {}

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
        HttpSession session = registerVerifyAndLogin(
                tenantSubdomain, "introspect-it-" + System.nanoTime() + "@example.com", "Str0ng!Passw0rd");

        MvcResult result = mockMvc.perform(get("/authorize")
                        .session((MockHttpSession) session)
                        .with(host(tenantSubdomain))
                        .param("client_id", clientIdValue)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_type", "code")
                        .param("scope", "openid offline_access")
                        .param("state", "xyz-state")
                        .param("code_challenge", codeChallenge)
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        Matcher matcher = CODE_PATTERN.matcher(result.getResponse().getRedirectedUrl());
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private IssuedTokens issueTokens(TenantAndClient ctx) throws Exception {
        String codeVerifier = randomCodeVerifier();
        String code = obtainAuthorizationCode(ctx.tenantSubdomain(), ctx.clientIdValue(), challengeFor(codeVerifier));

        MvcResult result = mockMvc.perform(post("/token")
                        .with(host(ctx.tenantSubdomain()))
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", codeVerifier))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, Object> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        return new IssuedTokens((String) body.get("access_token"), (String) body.get("refresh_token"));
    }

    @Test
    void introspectsARealAccessTokenAsActiveWithItsClaims() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-introspect-at", "acme-introspect-at-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(introspectRequest(ctx, tokens.accessToken(), null))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.client_id").value(ctx.clientIdValue()))
                .andExpect(jsonPath("$.scope").value(org.hamcrest.Matchers.containsString("openid")))
                .andExpect(jsonPath("$.sub").isNotEmpty())
                .andExpect(jsonPath("$.exp").isNumber())
                .andExpect(jsonPath("$.iat").isNumber());
    }

    @Test
    void introspectsARealRefreshTokenAsActiveWithItsClaims() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-introspect-rt", "acme-introspect-rt-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(introspectRequest(ctx, tokens.refreshToken(), "refresh_token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.token_type").value("refresh_token"))
                .andExpect(jsonPath("$.client_id").value(ctx.clientIdValue()))
                .andExpect(jsonPath("$.sub").isNotEmpty());
    }

    @Test
    void reportsInactiveForACompletelyUnknownToken() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-introspect-garbage", "acme-introspect-garbage-client");

        mockMvc.perform(introspectRequest(ctx, "not-a-real-token-at-all", null))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false))
                .andExpect(jsonPath("$.scope").doesNotExist())
                .andExpect(jsonPath("$.client_id").doesNotExist());
    }

    @Test
    void reportsInactiveForARevokedRefreshToken() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-introspect-revoked", "acme-introspect-revoked-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(revokeRequest(ctx, tokens.refreshToken())).andExpect(status().isOk());

        mockMvc.perform(introspectRequest(ctx, tokens.refreshToken(), "refresh_token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void rejectsIntrospectionWithNoClientCredentialsAtAll() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-introspect-nocreds", "acme-introspect-nocreds-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(post("/introspect").with(host(ctx.tenantSubdomain())).param("token", tokens.accessToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic"))
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void rejectsIntrospectionWithAWrongClientSecret() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-introspect-badsecret", "acme-introspect-badsecret-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(post("/introspect")
                        .with(host(ctx.tenantSubdomain()))
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(ctx.clientIdValue(), "wrong-secret"))
                        .param("token", tokens.accessToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void revokesARefreshTokenAndASubsequentRefreshGrantWithItFails() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-revoke-happy", "acme-revoke-happy-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(revokeRequest(ctx, tokens.refreshToken()))
                .andExpect(status().isOk())
                .andExpect(content().string(""));

        mockMvc.perform(post("/token")
                        .with(host(ctx.tenantSubdomain()))
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", tokens.refreshToken()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void revocationIsSilentlySuccessfulForACompletelyUnknownToken() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-revoke-unknown", "acme-revoke-unknown-client");

        mockMvc.perform(revokeRequest(ctx, "not-a-real-token-at-all")).andExpect(status().isOk());
    }

    @Test
    void revocationIsSilentlySuccessfulForAnAccessTokenSinceAccessTokensAreNotRevocable() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-revoke-at", "acme-revoke-at-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(revokeRequest(ctx, tokens.accessToken())).andExpect(status().isOk());
    }

    @Test
    void rejectsRevocationWithNoClientCredentialsAtAll() throws Exception {
        TenantAndClient ctx = provisionOfflineAccessClientAndSigningKey("acme-revoke-nocreds", "acme-revoke-nocreds-client");
        IssuedTokens tokens = issueTokens(ctx);

        mockMvc.perform(post("/revoke").with(host(ctx.tenantSubdomain())).param("token", tokens.refreshToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic"))
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder introspectRequest(
            TenantAndClient ctx, String token, String tokenTypeHint) {
        var builder = post("/introspect")
                .with(host(ctx.tenantSubdomain()))
                .header(HttpHeaders.AUTHORIZATION, basicAuth(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                .param("token", token);
        if (tokenTypeHint != null) {
            builder = builder.param("token_type_hint", tokenTypeHint);
        }
        return builder;
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder revokeRequest(
            TenantAndClient ctx, String token) {
        // Deliberately no .with(csrf()) here, same as /token - a real OAuth client never has a
        // CSRF token to present (see SecurityConfig's Javadoc), proving the exemption really works.
        return post("/revoke")
                .with(host(ctx.tenantSubdomain()))
                .header(HttpHeaders.AUTHORIZATION, basicAuth(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                .param("token", token);
    }

    private static org.springframework.test.web.servlet.request.RequestPostProcessor host(String tenantSubdomain) {
        return request -> {
            request.setServerName(tenantSubdomain);
            return request;
        };
    }

    private static String basicAuth(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    private void registerAndVerify(String tenantSubdomain, String email, String password) throws Exception {
        mockMvc.perform(post("/api/register")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf())
                .with(host(tenantSubdomain))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RegisterRequest(email, "Jane", "Doe", password))));
        String token = extractTokenFromLastMailLog();
        mockMvc.perform(post("/api/verify-email")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new VerifyEmailRequest(token))));
    }

    private HttpSession registerVerifyAndLogin(String tenantSubdomain, String email, String password) throws Exception {
        registerAndVerify(tenantSubdomain, email, password);

        MvcResult loginResult = mockMvc.perform(post("/api/login")
                        .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf())
                        .with(host(tenantSubdomain))
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
