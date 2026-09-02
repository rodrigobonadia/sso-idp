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
 * Exercises the server-rendered (Thymeleaf) "forgot my password" flow end-to-end: real Spring
 * context, real Postgres via Testcontainers, real {@link MockEmailSenderAdapter} - same
 * token-recovery approach as {@code LoginPageControllerIT}/{@code RegistrationPageControllerIT}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class ForgotPasswordPageControllerIT {

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
    void rendersTheForgotPasswordFormWithACsrfToken() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-forgot-page"));

        mockMvc.perform(get("/forgot-password").with(request -> {
                    request.setServerName("acme-forgot-page.localhost");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(view().name("forgot-password"))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    @Test
    void submittingForgotPasswordAlwaysRedirectsToCheckEmailRegardlessOfWhetherTheAccountExists() throws Exception {
        String tenantSubdomain = "acme-forgot-page-enum.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-forgot-page-enum"));
        registerAndVerify(tenantSubdomain, "existing@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/forgot-password")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "existing@example.com"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/forgot-password/check-email"));

        mockMvc.perform(post("/forgot-password")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "nobody-at-all@example.com"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/forgot-password/check-email"));
    }

    @Test
    void theResetLinkLetsTheUserSetANewPasswordAndTheSubmittingSessionNoLongerWorksAfterward() throws Exception {
        String tenantSubdomain = "acme-forgot-page-flow.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-forgot-page-flow"));
        registerAndVerify(tenantSubdomain, "resetflow@example.com", "Str0ng!Passw0rd");

        // This represents the case where the reset is submitted from the SAME browser session
        // that was still logged in with the old password (e.g. a stale tab). Per the current
        // scope decision (see AuthenticatedSessionEstablisher#invalidateCurrentSession's
        // Javadoc), a reset only guarantees invalidating the session that submits IT - it does
        // not reach across other devices/browsers where the user might also be logged in.
        HttpSession session = loginAndCaptureSession(tenantSubdomain, "resetflow@example.com", "Str0ng!Passw0rd");
        mockMvc.perform(get("/account").session((MockHttpSession) session)).andExpect(status().isOk());

        mockMvc.perform(post("/forgot-password")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "resetflow@example.com"))
                .andExpect(status().is3xxRedirection());

        String resetToken = extractTokenFromLastMailLog();

        mockMvc.perform(get("/reset-password").param("token", resetToken))
                .andExpect(status().isOk())
                .andExpect(view().name("reset-password"));

        mockMvc.perform(post("/reset-password")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .param("token", resetToken)
                        .param("newPassword", "N3wStr0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?password-reset"));

        // The session that submitted the reset must no longer be authenticated.
        mockMvc.perform(get("/account").session((MockHttpSession) session)).andExpect(status().isForbidden());

        // The new password now works; the old one no longer does.
        MvcResult reloginWithOldPassword = mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "resetflow@example.com")
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
                        .param("email", "resetflow@example.com")
                        .param("password", "N3wStr0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account"));
    }

    @Test
    void reRendersTheResetFormWithAnErrorForAnUnknownToken() throws Exception {
        mockMvc.perform(post("/reset-password")
                        .with(csrf())
                        .param("token", "dGhpc2lzbm90YXJlYWx0b2tlbnZhbHVl")
                        .param("newPassword", "N3wStr0ng!Passw0rd"))
                .andExpect(status().isOk())
                .andExpect(view().name("reset-password"));
    }

    @Test
    void reRendersTheResetFormForAWeakNewPasswordWithoutConsumingTheToken() throws Exception {
        String tenantSubdomain = "acme-forgot-page-weak.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-forgot-page-weak"));
        registerAndVerify(tenantSubdomain, "weakreset@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/forgot-password")
                .with(csrf())
                .with(request -> {
                    request.setServerName(tenantSubdomain);
                    return request;
                })
                .param("email", "weakreset@example.com"));
        String resetToken = extractTokenFromLastMailLog();

        mockMvc.perform(post("/reset-password").with(csrf()).param("token", resetToken).param("newPassword", "weak"))
                .andExpect(status().isOk())
                .andExpect(view().name("reset-password"));

        // The token must still be usable - the weak attempt above must not have consumed it.
        mockMvc.perform(post("/reset-password")
                        .with(csrf())
                        .param("token", resetToken)
                        .param("newPassword", "N3wStr0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?password-reset"));
    }

    @Test
    void aSuccessfulResetUnlocksALockedAccount() throws Exception {
        String tenantSubdomain = "acme-forgot-page-locked.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-forgot-page-locked"));
        registerAndVerify(tenantSubdomain, "lockedreset@example.com", "Str0ng!Passw0rd");

        // MAX_FAILED_LOGIN_ATTEMPTS wrong logins lock the account.
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/login")
                    .with(csrf())
                    .with(request -> {
                        request.setServerName(tenantSubdomain);
                        return request;
                    })
                    .param("email", "lockedreset@example.com")
                    .param("password", "totally-wrong"));
        }

        mockMvc.perform(post("/forgot-password")
                .with(csrf())
                .with(request -> {
                    request.setServerName(tenantSubdomain);
                    return request;
                })
                .param("email", "lockedreset@example.com"));
        String resetToken = extractTokenFromLastMailLog();

        mockMvc.perform(post("/reset-password")
                        .with(csrf())
                        .param("token", resetToken)
                        .param("newPassword", "N3wStr0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?password-reset"));

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "lockedreset@example.com")
                        .param("password", "N3wStr0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account"));
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
                .param("givenName", "Jane")
                .param("familyName", "Doe")
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
