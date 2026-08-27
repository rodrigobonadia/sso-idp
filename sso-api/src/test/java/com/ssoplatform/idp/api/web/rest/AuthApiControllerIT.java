package com.ssoplatform.idp.api.web.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.infrastructure.notification.MockEmailSenderAdapter;
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
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises the REST registration/verification/login flow end-to-end: real Spring context, real
 * Postgres via Testcontainers, real {@link MockEmailSenderAdapter} - the verification token
 * itself is recovered from that adapter's log line (via a Logback {@link ListAppender}), the same
 * way an operator reading the logs would, rather than reaching into persistence to cheat it out.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class AuthApiControllerIT {

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
    void registersAUserThenVerifiesTheirEmailWithTheTokenFromTheMockedEmail() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-register-api"));

        mockMvc.perform(post("/api/register")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-register-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RegisterRequest("someone@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("someone@example.com"))
                .andExpect(jsonPath("$.userId").exists());

        String token = extractTokenFromLastMailLog();

        mockMvc.perform(post("/api/verify-email")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-register-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new VerifyEmailRequest(token))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("someone@example.com"));
    }

    @Test
    void rejectsASecondVerificationAttemptWithTheSameTokenAsAConflict() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-reverify-api"));

        mockMvc.perform(post("/api/register")
                .with(csrf())
                .with(request -> {
                    request.setServerName("acme-reverify-api.localhost");
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                        new RegisterRequest("reverify@example.com", "Str0ng!Passw0rd"))));
        String token = extractTokenFromLastMailLog();

        mockMvc.perform(post("/api/verify-email")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new VerifyEmailRequest(token))))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/verify-email")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new VerifyEmailRequest(token))))
                .andExpect(status().isConflict());
    }

    @Test
    void rejectsRegistrationOfADuplicateEmailWithConflict() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-dup-email-api"));
        RegisterRequest request = new RegisterRequest("dup@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/register")
                .with(csrf())
                .with(req -> {
                    req.setServerName("acme-dup-email-api.localhost");
                    return req;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        mockMvc.perform(post("/api/register")
                        .with(csrf())
                        .with(req -> {
                            req.setServerName("acme-dup-email-api.localhost");
                            return req;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }

    @Test
    void rejectsRegistrationWithAWeakPasswordAsBadRequest() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-weak-pw-api"));

        mockMvc.perform(post("/api/register")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-weak-pw-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest("weak@example.com", "weak"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsRegistrationWhenTheRequestHasNoTenantSubdomain() throws Exception {
        mockMvc.perform(post("/api/register")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RegisterRequest("no-tenant@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void logsInAfterRegistrationAndVerificationAndRejectsAWrongPassword() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-login-api"));

        mockMvc.perform(post("/api/register")
                .with(csrf())
                .with(request -> {
                    request.setServerName("acme-login-api.localhost");
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                        new RegisterRequest("loginapi@example.com", "Str0ng!Passw0rd"))));
        String token = extractTokenFromLastMailLog();
        mockMvc.perform(post("/api/verify-email")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new VerifyEmailRequest(token))));

        mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-login-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("loginapi@example.com", "wrong-password"))))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-login-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("loginapi@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("loginapi@example.com"));
    }

    @Test
    void rejectsVerificationOfAnUnknownTokenAsNotFound() throws Exception {
        mockMvc.perform(post("/api/verify-email")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VerifyEmailRequest("dGhpc2lzbm90YXJlYWx0b2tlbnZhbHVl"))))
                .andExpect(status().isNotFound());
    }

    private String extractTokenFromLastMailLog() {
        String message =
                mailAppender.list.get(mailAppender.list.size() - 1).getFormattedMessage();
        Matcher matcher = TOKEN_PATTERN.matcher(message);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }
}
