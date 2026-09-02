package com.ssoplatform.idp.api.web.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

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
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.notification.MockEmailSenderAdapter;
import jakarta.servlet.http.HttpSession;
import java.nio.charset.StandardCharsets;
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
 * Exercises the whole Device Authorization Grant (RFC 8628) end-to-end: real Spring context, real
 * Postgres via Testcontainers, a real logged-in resource-owner session, and a real signed access
 * token from the actual {@code POST /token} device_code grant - covering both a confidential
 * client (HTTP Basic) and a public client (bare {@code client_id}), the Allow/Deny verification
 * page, and the {@code authorization_pending}/{@code access_denied} poll outcomes. Slow-down,
 * expiry, and every client-authentication edge case are already covered exhaustively at the
 * {@code TokenUseCase}/{@code RequestDeviceAuthorizationUseCase} unit-test level - this class
 * focuses on what only a real end-to-end run can prove: controller wiring, {@code SecurityConfig}
 * permissions, the login-and-resume mechanism for {@code GET /device}, real Thymeleaf view
 * resolution, and real JSON (de)serialization.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class DeviceAuthorizationFlowIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final Pattern TOKEN_PATTERN = Pattern.compile("token=([A-Za-z0-9_-]+)");
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

    private TenantAndClient provisionConfidentialDeviceClient(String tenantSlug, String clientIdValue) {
        CreateTenantResult tenant = createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", tenantSlug));
        OAuthClient client = OAuthClient.register(
                TenantId.of(tenant.tenantId()),
                ClientId.of(clientIdValue),
                clientSecretHasher.hash(RAW_CLIENT_SECRET),
                "Acme CLI",
                Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.DEVICE_CODE));
        oauthClientRepository.save(client);
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));
        return new TenantAndClient(tenantSlug + ".localhost", clientIdValue);
    }

    private TenantAndClient provisionPublicDeviceClient(String tenantSlug, String clientIdValue) {
        CreateTenantResult tenant = createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", tenantSlug));
        OAuthClient client = OAuthClient.register(
                TenantId.of(tenant.tenantId()),
                ClientId.of(clientIdValue),
                null,
                "Acme CLI (public)",
                Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.DEVICE_CODE));
        oauthClientRepository.save(client);
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));
        return new TenantAndClient(tenantSlug + ".localhost", clientIdValue);
    }

    @Test
    void requestsADeviceCodeForAConfidentialClient() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devauth-conf", "acme-devauth-conf-client");

        MvcResult result = mockMvc.perform(deviceAuthorizationRequest(tc.tenantSubdomain())
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(tc.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("scope", "openid profile"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.device_code").isNotEmpty())
                .andExpect(jsonPath("$.user_code").isNotEmpty())
                .andExpect(jsonPath("$.verification_uri").value("http://" + tc.tenantSubdomain() + ":8080/device"))
                .andExpect(jsonPath("$.expires_in").value(600))
                .andExpect(jsonPath("$.interval").value(5))
                .andReturn();

        Map<String, Object> body = objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
        assertThat((String) body.get("user_code")).matches("^[A-Z0-9]{4}-[A-Z0-9]{4}$");
        assertThat((String) body.get("verification_uri_complete"))
                .startsWith((String) body.get("verification_uri") + "?user_code=");
    }

    @Test
    void requestsADeviceCodeForAPublicClientWithNoSecret() throws Exception {
        TenantAndClient tc = provisionPublicDeviceClient("acme-devauth-pub", "acme-devauth-pub-client");

        mockMvc.perform(deviceAuthorizationRequest(tc.tenantSubdomain())
                        .param("client_id", tc.clientIdValue())
                        .param("scope", "openid"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.device_code").isNotEmpty());
    }

    @Test
    void rejectsADeviceAuthorizationRequestWithNoClientCredentialsAtAll() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devauth-nocreds", "acme-devauth-nocreds-client");

        mockMvc.perform(deviceAuthorizationRequest(tc.tenantSubdomain()).param("scope", "openid"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic"))
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void rejectsAScopeTheClientIsNotAllowed() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devauth-badscope", "acme-devauth-badscope-client");

        mockMvc.perform(deviceAuthorizationRequest(tc.tenantSubdomain())
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(tc.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("scope", "email"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    @Test
    void completeDeviceFlowConfidentialClientApprovedByUser() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devflow-ok", "acme-devflow-ok-client");
        Map<String, Object> authz = requestDeviceCode(tc, tc.clientIdValue(), true);
        String deviceCode = (String) authz.get("device_code");
        String userCode = (String) authz.get("user_code");

        HttpSession session =
                registerVerifyAndLogin(tc.tenantSubdomain(), "devflow-ok@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(get("/device").session((MockHttpSession) session).with(host(tc.tenantSubdomain())))
                .andExpect(status().isOk())
                .andExpect(view().name("device"));

        mockMvc.perform(post("/device")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(host(tc.tenantSubdomain()))
                        .param("user_code", userCode))
                .andExpect(status().isOk())
                .andExpect(view().name("device-confirm"));

        mockMvc.perform(post("/device/allow")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(host(tc.tenantSubdomain()))
                        .param("user_code", userCode))
                .andExpect(status().isOk())
                .andExpect(view().name("device-result"));

        MvcResult tokenResult = mockMvc.perform(tokenRequest(tc.tenantSubdomain())
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(tc.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("device_code", deviceCode))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.id_token").isNotEmpty())
                .andReturn();

        Map<String, Object> tokenBody =
                objectMapper.readValue(tokenResult.getResponse().getContentAsString(), Map.class);
        Map<String, Object> claims = decodeJwtPayload((String) tokenBody.get("access_token"));
        assertThat((String) claims.get("scope")).contains("openid");
    }

    @Test
    void completeDeviceFlowPublicClientApprovedByUser() throws Exception {
        TenantAndClient tc = provisionPublicDeviceClient("acme-devflow-pub", "acme-devflow-pub-client");
        Map<String, Object> authz = requestDeviceCode(tc, tc.clientIdValue(), false);
        String deviceCode = (String) authz.get("device_code");
        String userCode = (String) authz.get("user_code");

        HttpSession session =
                registerVerifyAndLogin(tc.tenantSubdomain(), "devflow-pub@example.com", "Str0ng!Passw0rd");
        mockMvc.perform(post("/device")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(host(tc.tenantSubdomain()))
                        .param("user_code", userCode))
                .andExpect(status().isOk());
        mockMvc.perform(post("/device/allow")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(host(tc.tenantSubdomain()))
                        .param("user_code", userCode))
                .andExpect(status().isOk());

        mockMvc.perform(tokenRequest(tc.tenantSubdomain())
                        .param("client_id", tc.clientIdValue())
                        .param("device_code", deviceCode))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void pollingBeforeTheUserActsReturnsAuthorizationPending() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devflow-pending", "acme-devflow-pending-client");
        Map<String, Object> authz = requestDeviceCode(tc, tc.clientIdValue(), true);

        mockMvc.perform(tokenRequest(tc.tenantSubdomain())
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(tc.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("device_code", (String) authz.get("device_code")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("authorization_pending"));
    }

    @Test
    void deviceFlowDeniedByUserReturnsAccessDeniedToThePollingDevice() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devflow-deny", "acme-devflow-deny-client");
        Map<String, Object> authz = requestDeviceCode(tc, tc.clientIdValue(), true);
        String deviceCode = (String) authz.get("device_code");
        String userCode = (String) authz.get("user_code");

        HttpSession session =
                registerVerifyAndLogin(tc.tenantSubdomain(), "devflow-deny@example.com", "Str0ng!Passw0rd");
        mockMvc.perform(post("/device")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(host(tc.tenantSubdomain()))
                        .param("user_code", userCode))
                .andExpect(status().isOk());
        mockMvc.perform(post("/device/deny")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(host(tc.tenantSubdomain()))
                        .param("user_code", userCode))
                .andExpect(status().isOk())
                .andExpect(view().name("device-result"));

        mockMvc.perform(tokenRequest(tc.tenantSubdomain())
                        .header(HttpHeaders.AUTHORIZATION, basicAuth(tc.clientIdValue(), RAW_CLIENT_SECRET))
                        .param("device_code", deviceCode))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("access_denied"));
    }

    @Test
    void enteringAnUnknownUserCodeReRendersTheFormWithAnError() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devflow-badcode", "acme-devflow-badcode-client");
        HttpSession session =
                registerVerifyAndLogin(tc.tenantSubdomain(), "devflow-badcode@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/device")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(host(tc.tenantSubdomain()))
                        .param("user_code", "ZZZZ-9999"))
                .andExpect(status().isOk())
                .andExpect(view().name("device"));
    }

    @Test
    void unauthenticatedDeviceRedirectsToLoginThenResumesAfterSignIn() throws Exception {
        TenantAndClient tc = provisionConfidentialDeviceClient("acme-devflow-resume", "acme-devflow-resume-client");
        registerAndVerify(tc.tenantSubdomain(), "devflow-resume@example.com", "Str0ng!Passw0rd");

        MvcResult unauthenticated = mockMvc.perform(get("/device").with(host(tc.tenantSubdomain())))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        assertThat(unauthenticated.getResponse().getRedirectedUrl()).endsWith("/login");
        MockHttpSession session = (MockHttpSession) unauthenticated.getRequest().getSession(false);
        assertThat(session).isNotNull();

        MvcResult loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .session(session)
                        .with(host(tc.tenantSubdomain()))
                        .param("email", "devflow-resume@example.com")
                        .param("password", "Str0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        assertThat(loginResult.getResponse().getRedirectedUrl()).contains("/device");

        mockMvc.perform(get("/device").session(session).with(host(tc.tenantSubdomain())))
                .andExpect(status().isOk())
                .andExpect(view().name("device"));
    }

    private Map<String, Object> requestDeviceCode(TenantAndClient tc, String clientIdValue, boolean confidential)
            throws Exception {
        var request = deviceAuthorizationRequest(tc.tenantSubdomain()).param("scope", "openid profile");
        if (confidential) {
            request = request.header(HttpHeaders.AUTHORIZATION, basicAuth(clientIdValue, RAW_CLIENT_SECRET));
        } else {
            request = request.param("client_id", clientIdValue);
        }
        MvcResult result = mockMvc.perform(request).andExpect(status().isOk()).andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), Map.class);
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder deviceAuthorizationRequest(
            String tenantSubdomain) {
        return post("/device_authorization").with(host(tenantSubdomain));
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder tokenRequest(
            String tenantSubdomain) {
        return post("/token")
                .with(host(tenantSubdomain))
                .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
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
                .with(csrf())
                .with(host(tenantSubdomain))
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

    private Map<String, Object> decodeJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        return objectMapper.readValue(Base64.getUrlDecoder().decode(parts[1]), Map.class);
    }
}
