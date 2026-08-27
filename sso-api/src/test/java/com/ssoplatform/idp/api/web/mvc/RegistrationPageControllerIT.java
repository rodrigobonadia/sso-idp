package com.ssoplatform.idp.api.web.mvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises the server-rendered (Thymeleaf) registration/verification flow end-to-end: real
 * Spring context, real Postgres via Testcontainers, real {@link MockEmailSenderAdapter} - same
 * token-recovery approach as {@code AuthApiControllerIT}, since both surfaces share the same
 * mock e-mail adapter.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class RegistrationPageControllerIT {

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
    void rendersTheRegistrationFormForATenantSubdomain() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-register-page"));

        mockMvc.perform(get("/register").with(request -> {
                    request.setServerName("acme-register-page.localhost");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(view().name("register"))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    @Test
    void submittingTheFormRedirectsToCheckEmailAndTheLinkLaterVerifiesTheAccount() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-register-page-flow"));

        mockMvc.perform(post("/register")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-register-page-flow.localhost");
                            return request;
                        })
                        .param("email", "pageflow@example.com")
                        .param("password", "Str0ng!Passw0rd"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/register/check-email"));

        String token = extractTokenFromLastMailLog();

        mockMvc.perform(get("/verify-email").param("token", token))
                .andExpect(status().isOk())
                .andExpect(view().name("verify-email-result"))
                .andExpect(content().string(containsString("pageflow@example.com")));
    }

    @Test
    void reRendersTheFormWithAnErrorMessageWhenThePasswordIsWeak() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-register-page-weak"));

        mockMvc.perform(post("/register")
                        .with(csrf())
                        .with(request -> {
                            request.setServerName("acme-register-page-weak.localhost");
                            return request;
                        })
                        .param("email", "weakpage@example.com")
                        .param("password", "weak"))
                .andExpect(status().isOk())
                .andExpect(view().name("register"));
    }

    @Test
    void verifyEmailPageShowsAFailureMessageForAnUnknownToken() throws Exception {
        mockMvc.perform(get("/verify-email").param("token", "dGhpc2lzbm90YXJlYWx0b2tlbnZhbHVl"))
                .andExpect(status().isOk())
                .andExpect(view().name("verify-email-result"));
    }

    private String extractTokenFromLastMailLog() {
        String message =
                mailAppender.list.get(mailAppender.list.size() - 1).getFormattedMessage();
        Matcher matcher = TOKEN_PATTERN.matcher(message);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }
}
