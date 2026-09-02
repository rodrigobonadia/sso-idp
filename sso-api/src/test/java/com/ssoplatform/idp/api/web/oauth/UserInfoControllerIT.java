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
 * Exercises {@code GET /userinfo} end-to-end: real Spring context, real Postgres via
 * Testcontainers, a real access token obtained through the full authorize-then-redeem round trip
 * (exactly like {@code TokenControllerIT}), presented back as a genuine {@code Authorization:
 * Bearer} header - proving the whole chain (signing key generation, JWT signing at {@code /token},
 * JWT verification at {@code /userinfo}) actually interoperates.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class UserInfoControllerIT {

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

    private TenantAndClient provisionTenantClientAndSigningKey(String tenantSlug, String clientIdValue) {
        CreateTenantResult tenant = createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", tenantSlug));
        OAuthClient client = OAuthClient.register(
                TenantId.of(tenant.tenantId()),
                ClientId.of(clientIdValue),
                clientSecretHasher.hash(RAW_CLIENT_SECRET),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI)),
                Set.of("openid", "profile", "email"),
                Set.of(GrantType.AUTHORIZATION_CODE));
        oauthClientRepository.save(client);
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));
        return new TenantAndClient(tenantSlug + ".localhost", clientIdValue);
    }

    private static String randomCodeVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String challengeFor(String codeVerifier) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private String obtainAccessToken(TenantAndClient ctx, String scope) throws Exception {
        String codeVerifier = randomCodeVerifier();
        String codeChallenge = challengeFor(codeVerifier);
        HttpSession session = registerVerifyAndLogin(
                ctx.tenantSubdomain(), "userinfo-it-" + System.nanoTime() + "@example.com", "Str0ng!Passw0rd");

        MvcResult authorizeResult = mockMvc.perform(get("/authorize")
                        .session((MockHttpSession) session)
                        .with(request -> {
                            request.setServerName(ctx.tenantSubdomain());
                            return request;
                        })
                        .param("client_id", ctx.clientIdValue())
                        .param("redirect_uri", REDIRECT_URI)
                        .param("response_type", "code")
                        .param("scope", scope)
                        .param("state", "xyz-state")
                        .param("code_challenge", codeChallenge)
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        Matcher matcher = CODE_PATTERN.matcher(authorizeResult.getResponse().getRedirectedUrl());
        assertThat(matcher.find()).isTrue();
        String code = matcher.group(1);

        MvcResult tokenResult = mockMvc.perform(post("/token")
                        .with(request -> {
                            request.setServerName(ctx.tenantSubdomain());
                            return request;
                        })
                        .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(ctx.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", codeVerifier))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, Object> body =
                objectMapper.readValue(tokenResult.getResponse().getContentAsString(), Map.class);
        return (String) body.get("access_token");
    }

    private static String basicAuthHeader(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
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

    @Test
    void returnsEveryGrantedClaimForAFullyScopedAccessToken() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-userinfo-full", "acme-userinfo-full-client");
        String accessToken = obtainAccessToken(ctx, "openid profile email");

        mockMvc.perform(get("/userinfo")
                        .with(request -> {
                            request.setServerName(ctx.tenantSubdomain());
                            return request;
                        })
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists())
                .andExpect(jsonPath("$.email").value(org.hamcrest.Matchers.startsWith("userinfo-it-")))
                .andExpect(jsonPath("$.email_verified").value(true))
                .andExpect(jsonPath("$.given_name").value("Jane"))
                .andExpect(jsonPath("$.family_name").value("Doe"))
                .andExpect(jsonPath("$.name").value("Jane Doe"));
    }

    @Test
    void omitsEveryClaimNotGrantedByTheTokensScope() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-userinfo-bare", "acme-userinfo-bare-client");
        String accessToken = obtainAccessToken(ctx, "openid");

        mockMvc.perform(get("/userinfo")
                        .with(request -> {
                            request.setServerName(ctx.tenantSubdomain());
                            return request;
                        })
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").exists())
                .andExpect(jsonPath("$.email").doesNotExist())
                .andExpect(jsonPath("$.given_name").doesNotExist())
                .andExpect(jsonPath("$.name").doesNotExist());
    }

    @Test
    void rejectsARequestWithNoAuthorizationHeaderAsInvalidRequest() throws Exception {
        TenantAndClient ctx = provisionTenantClientAndSigningKey("acme-userinfo-noauth", "acme-userinfo-noauth-client");

        mockMvc.perform(get("/userinfo").with(request -> {
                    request.setServerName(ctx.tenantSubdomain());
                    return request;
                }))
                .andExpect(status().isBadRequest())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, org.hamcrest.Matchers.containsString(
                        "error=\"invalid_request\"")))
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void rejectsAMalformedBearerTokenAsInvalidToken() throws Exception {
        TenantAndClient ctx =
                provisionTenantClientAndSigningKey("acme-userinfo-malformed", "acme-userinfo-malformed-client");

        mockMvc.perform(get("/userinfo")
                        .with(request -> {
                            request.setServerName(ctx.tenantSubdomain());
                            return request;
                        })
                        .header(HttpHeaders.AUTHORIZATION, "Bearer not-a-real-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(
                        HttpHeaders.WWW_AUTHENTICATE, org.hamcrest.Matchers.containsString("error=\"invalid_token\"")))
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }

    @Test
    void rejectsAnAccessTokenPresentedToADifferentTenantAsInvalidToken() throws Exception {
        TenantAndClient issuingTenant =
                provisionTenantClientAndSigningKey("acme-userinfo-cross-a", "acme-userinfo-cross-a-client");
        TenantAndClient otherTenant =
                provisionTenantClientAndSigningKey("acme-userinfo-cross-b", "acme-userinfo-cross-b-client");
        String accessToken = obtainAccessToken(issuingTenant, "openid profile email");

        mockMvc.perform(get("/userinfo")
                        .with(request -> {
                            request.setServerName(otherTenant.tenantSubdomain());
                            return request;
                        })
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_token"));
    }
}
