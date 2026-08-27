package com.ssoplatform.idp.api.web.mvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises the server-rendered (Thymeleaf) authenticated "change my password" flow end-to-end:
 * real Spring context, real Postgres via Testcontainers. Unlike {@code ForgotPasswordPageControllerIT},
 * this flow needs an existing session to even reach the form - see {@code LoginPageControllerIT}
 * for the session-capture-and-replay technique used here.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class ChangePasswordPageControllerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final Pattern TOKEN_PATTERN = Pattern.compile("token=([A-Za-z0-9_-]+)");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

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
    void accessingWithoutASessionIsForbidden() throws Exception {
        mockMvc.perform(get("/account/change-password")).andExpect(status().isForbidden());
    }

    @Test
    void rendersTheChangePasswordFormWithACsrfTokenWhenAuthenticated() throws Exception {
        String tenantSubdomain = "acme-changepw-page.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-changepw-page"));
        registerAndVerify(tenantSubdomain, "changepwpage@example.com", "Str0ng!Passw0rd");
        HttpSession session =
                loginAndCaptureSession(tenantSubdomain, "changepwpage@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(get("/account/change-password").session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andExpect(view().name("change-password"))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    @Test
    void changesThePasswordWhenTheCurrentPasswordIsCorrectAndInvalidatesTheOldSession() throws Exception {
        String tenantSubdomain = "acme-changepw-flow.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-changepw-flow"));
        registerAndVerify(tenantSubdomain, "changepwflow@example.com", "Str0ng!Passw0rd");
        HttpSession session =
                loginAndCaptureSession(tenantSubdomain, "changepwflow@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .param("currentPassword", "Str0ng!Passw0rd")
                        .param("newPassword", "N3wStr0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?password-changed"));

        // The very session that just changed the password must no longer be authenticated.
        mockMvc.perform(get("/account").session((MockHttpSession) session)).andExpect(status().isForbidden());

        MvcResult reloginWithOldPassword = mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "changepwflow@example.com")
                        .param("password", "Str0ng!Passw0rd"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andReturn();
        assertThat(reloginWithOldPassword.getResponse().getContentAsString()).contains("Invalid e-mail or password");

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "changepwflow@example.com")
                        .param("password", "N3wStr0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account"));
    }

    @Test
    void reRendersTheFormWithAnErrorForAnIncorrectCurrentPasswordAndKeepsTheSessionValid() throws Exception {
        String tenantSubdomain = "acme-changepw-wrong.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-changepw-wrong"));
        registerAndVerify(tenantSubdomain, "changepwwrong@example.com", "Str0ng!Passw0rd");
        HttpSession session =
                loginAndCaptureSession(tenantSubdomain, "changepwwrong@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .param("currentPassword", "totally-wrong")
                        .param("newPassword", "N3wStr0ng!Passw0rd"))
                .andExpect(status().isOk())
                .andExpect(view().name("change-password"));

        // A failed attempt must not invalidate the still-valid session.
        mockMvc.perform(get("/account").session((MockHttpSession) session)).andExpect(status().isOk());
    }

    @Test
    void reRendersTheFormForAWeakNewPassword() throws Exception {
        String tenantSubdomain = "acme-changepw-weak.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-changepw-weak"));
        registerAndVerify(tenantSubdomain, "changepwweak@example.com", "Str0ng!Passw0rd");
        HttpSession session =
                loginAndCaptureSession(tenantSubdomain, "changepwweak@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .param("currentPassword", "Str0ng!Passw0rd")
                        .param("newPassword", "weak"))
                .andExpect(status().isOk())
                .andExpect(view().name("change-password"));
    }

    private HttpSession loginAndCaptureSession(String tenantSubdomain, String email, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", email)
                        .param("password", password))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        HttpSession session = result.getRequest().getSession(false);
        assertThat(session).isNotNull();
        return session;
    }

    private void registerAndVerify(String tenantSubdomain, String email, String password) throws Exception {
        mockMvc.perform(post("/register")
                .with(csrf())
                .with(request -> {
                    request.setServerName(tenantSubdomain);
                    return request;
                })
                .param("email", email)
                .param("password", password));

        String token = extractTokenFromLastMailLog();

        mockMvc.perform(get("/verify-email").param("token", token));
    }

    private String extractTokenFromLastMailLog() {
        String message =
                mailAppender.list.get(mailAppender.list.size() - 1).getFormattedMessage();
        Matcher matcher = TOKEN_PATTERN.matcher(message);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }
}
