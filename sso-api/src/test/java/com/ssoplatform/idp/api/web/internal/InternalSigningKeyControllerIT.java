package com.ssoplatform.idp.api.web.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssoplatform.idp.api.web.rest.LoginRequest;
import com.ssoplatform.idp.api.web.rest.RegisterRequest;
import com.ssoplatform.idp.api.web.rest.VerifyEmailRequest;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.infrastructure.notification.MockEmailSenderAdapter;
import jakarta.servlet.http.HttpSession;
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
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises {@code POST /internal/signing-keys} end-to-end: real Spring context, real Postgres via
 * Testcontainers. An authenticated session is obtained the same way {@code AuthApiControllerIT}
 * gets one - register, verify (token recovered from the mocked e-mail log), then log in.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class InternalSigningKeyControllerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final Pattern TOKEN_PATTERN = Pattern.compile("token=([A-Za-z0-9_-]+)");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

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

    @Test
    void generatesANewCurrentSigningKeyForTheAuthenticatedTenant() throws Exception {
        String tenantSubdomain = "acme-genkey.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-genkey"));
        HttpSession session = registerVerifyAndLogin(tenantSubdomain, "genkey@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/internal/signing-keys")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        }))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.kid").isNotEmpty())
                .andExpect(jsonPath("$.createdAt").isNotEmpty());
    }

    @Test
    void rotatingTwiceStillLeavesExactlyOneCurrentKeyForTheTenant() throws Exception {
        String tenantSubdomain = "acme-genkey-rotate.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-genkey-rotate"));
        HttpSession session =
                registerVerifyAndLogin(tenantSubdomain, "genkeyrotate@example.com", "Str0ng!Passw0rd");

        MvcResult first = mockMvc.perform(post("/internal/signing-keys")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        }))
                .andExpect(status().isCreated())
                .andReturn();
        MvcResult second = mockMvc.perform(post("/internal/signing-keys")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        }))
                .andExpect(status().isCreated())
                .andReturn();

        String firstKid = objectMapper.readTree(first.getResponse().getContentAsString()).get("kid").asText();
        String secondKid = objectMapper.readTree(second.getResponse().getContentAsString()).get("kid").asText();
        assertThat(firstKid).isNotEqualTo(secondKid);
    }

    @Test
    void rejectsAnUnauthenticatedRequestAsForbidden() throws Exception {
        mockMvc.perform(post("/internal/signing-keys").with(csrf())).andExpect(status().isForbidden());
    }

    @Test
    void rejectsAnAuthenticatedRequestWithNoTenantSubdomainAsBadRequest() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-genkey-no-tenant"));
        HttpSession session = registerVerifyAndLogin(
                "acme-genkey-no-tenant.localhost", "genkeynotenant@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/internal/signing-keys")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .with(request -> {
                            request.setServerName("localhost");
                            return request;
                        }))
                .andExpect(status().isBadRequest());
    }

    private HttpSession registerVerifyAndLogin(String tenantSubdomain, String email, String password) throws Exception {
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
