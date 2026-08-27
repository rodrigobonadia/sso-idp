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

    @Test
    void forgotPasswordAlwaysRespondsTheSameWayRegardlessOfWhetherTheAccountExists() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-forgot-api"));

        mockMvc.perform(post("/api/forgot-password")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-forgot-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ForgotPasswordRequest("nobody@example.com"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void resetsThePasswordFromTheMockedEmailAndRejectsTheOldPasswordAfterward() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-reset-api"));
        registerVerifyAndLogin("acme-reset-api.localhost", "resetapi@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/forgot-password")
                .with(csrf())
                .with(request -> {
                    request.setServerName("acme-reset-api.localhost");
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new ForgotPasswordRequest("resetapi@example.com"))));
        String resetToken = extractTokenFromLastMailLog();

        mockMvc.perform(post("/api/reset-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest(resetToken, "N3wStr0ng!Passw0rd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("resetapi@example.com"));

        mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-reset-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("resetapi@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-reset-api.localhost");
                            return request;
                        })
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("resetapi@example.com", "N3wStr0ng!Passw0rd"))))
                .andExpect(status().isOk());
    }

    @Test
    void rejectsResetWithAnUnknownTokenAsNotFound() throws Exception {
        mockMvc.perform(post("/api/reset-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ResetPasswordRequest(
                                "dGhpc2lzbm90YXJlYWx0b2tlbnZhbHVl", "N3wStr0ng!Passw0rd"))))
                .andExpect(status().isNotFound());
    }

    @Test
    void changesThePasswordWhenAuthenticatedAndInvalidatesTheOldSession() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-changepw-api"));
        HttpSession session =
                registerVerifyAndLogin("acme-changepw-api.localhost", "changepwapi@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/account/change-password")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ChangePasswordRequest("Str0ng!Passw0rd", "N3wStr0ng!Passw0rd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("changepwapi@example.com"));

        // The very session that just changed the password must no longer be authenticated.
        mockMvc.perform(post("/api/account/change-password")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ChangePasswordRequest("N3wStr0ng!Passw0rd", "AnotherStr0ng!Pass"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void rejectsChangePasswordWithAnIncorrectCurrentPasswordAsBadRequest() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-changepw-wrong-api"));
        HttpSession session = registerVerifyAndLogin(
                "acme-changepw-wrong-api.localhost", "changepwwrongapi@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/account/change-password")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ChangePasswordRequest("totally-wrong", "N3wStr0ng!Passw0rd"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsChangePasswordWithoutAnAuthenticatedSessionAsForbidden() throws Exception {
        mockMvc.perform(post("/api/account/change-password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ChangePasswordRequest("whatever", "N3wStr0ng!Passw0rd"))))
                .andExpect(status().isForbidden());
    }

    private HttpSession registerVerifyAndLogin(String tenantSubdomain, String email, String password) throws Exception {
        mockMvc.perform(post("/api/register")
                .with(csrf())
                .with(request -> {
                    request.setServerName(tenantSubdomain);
                    return request;
                })
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RegisterRequest(email, password))));
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
        String message =
                mailAppender.list.get(mailAppender.list.size() - 1).getFormattedMessage();
        Matcher matcher = TOKEN_PATTERN.matcher(message);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }
}
