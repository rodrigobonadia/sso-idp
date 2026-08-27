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
 * Exercises the server-rendered (Thymeleaf) login/logout flow end-to-end: real Spring context,
 * real Postgres via Testcontainers, real {@link MockEmailSenderAdapter}. A successful login's
 * {@code HttpSession} is captured from one request and replayed on the next, the same way a real
 * browser would carry the session cookie forward - this is what proves {@link
 * com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher} actually persisted the
 * authentication rather than it only living on the thread that handled the login request.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class LoginPageControllerIT {

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
    void rendersTheLoginFormWithACsrfToken() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-login-page"));

        mockMvc.perform(get("/login").with(request -> {
                    request.setServerName("acme-login-page.localhost");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    @Test
    void logsInAfterVerificationAndReachesTheAccountPageWithTheSameSession() throws Exception {
        String tenantSubdomain = "acme-login-page-flow.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-login-page-flow"));
        registerAndVerify(tenantSubdomain, "pageloginflow@example.com", "Str0ng!Passw0rd");

        MvcResult loginResult = mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "pageloginflow@example.com")
                        .param("password", "Str0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account"))
                .andReturn();

        HttpSession session = loginResult.getRequest().getSession(false);
        assertThat(session).isNotNull();

        mockMvc.perform(get("/account").session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andExpect(view().name("account"))
                .andExpect(content().string(containsString("pageloginflow@example.com")));
    }

    @Test
    void reRendersTheLoginFormWithAGenericErrorForAWrongPassword() throws Exception {
        String tenantSubdomain = "acme-login-page-wrong.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-login-page-wrong"));
        registerAndVerify(tenantSubdomain, "wrongpw@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "wrongpw@example.com")
                        .param("password", "totally-wrong"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    void rejectsLoginForAnAccountThatHasNotVerifiedItsEmailYet() throws Exception {
        String tenantSubdomain = "acme-login-page-unverified.localhost";
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-login-page-unverified"));

        mockMvc.perform(post("/register")
                .with(csrf())
                .with(request -> {
                    request.setServerName(tenantSubdomain);
                    return request;
                })
                .param("email", "unverified@example.com")
                .param("password", "Str0ng!Passw0rd"));

        mockMvc.perform(post("/login")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName(tenantSubdomain);
                            return request;
                        })
                        .param("email", "unverified@example.com")
                        .param("password", "Str0ng!Passw0rd"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    void accessingTheAccountPageWithoutASessionIsForbidden() throws Exception {
        mockMvc.perform(get("/account")).andExpect(status().isForbidden());
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
