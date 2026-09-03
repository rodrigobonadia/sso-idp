package com.ssoplatform.idp.api.web.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.infrastructure.notification.MockEmailSenderAdapter;
import jakarta.servlet.http.HttpSession;
import java.util.List;
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
 * Exercises the complete Phase 4.2 e-mail OTP MFA flow end-to-end: real Spring context, real
 * Postgres via Testcontainers, and the real code {@code MockEmailSenderAdapter} logs (the only
 * "delivery channel" this phase has) read back exactly as a user reading their inbox would.
 * Mirrors {@code MfaApiControllerIT}'s structure (Phase 4.1, TOTP) test-for-test wherever the two
 * methods share a shape - enable/confirm, the challenge round trip, recovery-code fallback,
 * disable - since {@code MfaDisableUseCase} and the {@code /api/login} MFA-required branch serve
 * both methods identically. What is genuinely new here and has no TOTP analogue is exercised in
 * its own dedicated tests: the per-code {@code MAX_FAILED_ATTEMPTS} lockout ({@code EmailOtpCode}),
 * and {@code mfaMethod: "EMAIL_OTP"} appearing on the login response. Every exception-path edge
 * case already has dedicated unit-test coverage at the use-case level (see {@code
 * sso-application}'s {@code usecase.mfa} package) - this class instead proves what only a real
 * end-to-end run can: controller wiring, {@code SecurityConfig}'s permissions, and the real
 * interaction between enrollment, a subsequent password-based login, and the MFA challenge round
 * trip.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class EmailOtpApiControllerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final Pattern TOKEN_PATTERN = Pattern.compile("token=([A-Za-z0-9_-]+)");

    /**
     * {@code MockEmailSenderAdapter#sendMfaEmailOtpCode} logs {@code "... code for {email}:
     * {code}"} - matching on the trailing ": 123456" (rather than trying to also match the e-mail
     * address itself) keeps this pattern correct regardless of what the recipient address is.
     */
    private static final Pattern OTP_CODE_PATTERN = Pattern.compile(": (\\d{6})$");

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

    private record EnrollmentResult(List<String> recoveryCodes) {}

    @Test
    void enablingReturnsAMaskedEmailAndSendsAConfirmationCode() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-enable"));
        HttpSession session =
                registerVerifyAndLogin("acme-eotp-enable.localhost", "eotp-enable@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/mfa/email-otp/enable").with(csrf()).session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maskedEmail").value("e***e@example.com"));

        assertThat(extractOtpCodeFromLastMailLog()).matches("\\d{6}");
    }

    @Test
    void confirmingWithACorrectCodeActivatesEmailOtpAndReturnsTenRecoveryCodes() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-confirm"));
        HttpSession session =
                registerVerifyAndLogin("acme-eotp-confirm.localhost", "eotp-confirm@example.com", "Str0ng!Passw0rd");

        EnrollmentResult enrollment = enableAndConfirmEmailOtp(session);

        assertThat(enrollment.recoveryCodes()).hasSize(10);
        assertThat(enrollment.recoveryCodes())
                .allMatch(code -> code.matches("[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}"));
    }

    @Test
    void confirmingWithAWrongCodeIsRejectedAndAGenuineRetryStillSucceeds() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-wrongconfirm"));
        HttpSession session = registerVerifyAndLogin(
                "acme-eotp-wrongconfirm.localhost", "eotp-wrongconfirm@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/mfa/email-otp/enable").with(csrf()).session((MockHttpSession) session))
                .andExpect(status().isOk());
        String correctCode = extractOtpCodeFromLastMailLog();

        // A wrong e-mail OTP code at confirmation time is InvalidMfaCodeException (401), not a
        // request-shape problem - any other well-formed 6-digit string is perfectly valid input.
        mockMvc.perform(post("/api/mfa/email-otp/confirm")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaConfirmRequest(wrongCodeFor(correctCode)))))
                .andExpect(status().isUnauthorized());

        // The pending enrollment survives a wrong attempt - a genuine retry with the correct code
        // against the SAME still-pending credential must still succeed rather than needing to
        // re-enable from scratch.
        mockMvc.perform(post("/api/mfa/email-otp/confirm")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaConfirmRequest(correctCode))))
                .andExpect(status().isOk());
    }

    @Test
    void confirmingAfterFiveFailedAttemptsIsRejectedWithTooManyRequestsEvenWithTheCorrectCode() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-lockout"));
        HttpSession session =
                registerVerifyAndLogin("acme-eotp-lockout.localhost", "eotp-lockout@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/mfa/email-otp/enable").with(csrf()).session((MockHttpSession) session))
                .andExpect(status().isOk());
        String correctCode = extractOtpCodeFromLastMailLog();
        String wrongCode = wrongCodeFor(correctCode);

        // EmailOtpCode.MAX_FAILED_ATTEMPTS is 5: recording the 5th failed attempt still succeeds
        // (it is the one that reaches the limit), so five wrong attempts in a row are each
        // individually rejected as a plain 401 - only the NEXT check after that finds the limit
        // already exceeded.
        for (int attempt = 1; attempt <= 5; attempt++) {
            mockMvc.perform(post("/api/mfa/email-otp/confirm")
                            .with(csrf())
                            .session((MockHttpSession) session)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(new MfaConfirmRequest(wrongCode))))
                    .andExpect(status().isUnauthorized());
        }

        // The 6th check - even presenting the CORRECT code this time - finds the attempt limit
        // already permanently exhausted: 429, not 200.
        mockMvc.perform(post("/api/mfa/email-otp/confirm")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaConfirmRequest(correctCode))))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void loginIssuesAnMfaChallengeWithTheEmailOtpMethodAndSendsAFreshCode() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-challenge"));
        HttpSession session = registerVerifyAndLogin(
                "acme-eotp-challenge.localhost", "eotp-challenge@example.com", "Str0ng!Passw0rd");
        enableAndConfirmEmailOtp(session);

        MvcResult loginResult = mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(host("acme-eotp-challenge.localhost"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("eotp-challenge@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.challengeToken").isNotEmpty())
                .andExpect(jsonPath("$.mfaMethod").value("EMAIL_OTP"))
                .andReturn();

        // No session was established by a challenge-only login.
        assertThat(loginResult.getRequest().getSession(false)).isNull();
        // Logging in issued a brand-new challenge code by e-mail, exactly like the confirmation
        // step did during enrollment.
        assertThat(extractOtpCodeFromLastMailLog()).matches("\\d{6}");
    }

    @Test
    void verifiesTheChallengeWithACorrectEmailOtpCodeAndEstablishesASession() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-verify"));
        HttpSession session =
                registerVerifyAndLogin("acme-eotp-verify.localhost", "eotp-verify@example.com", "Str0ng!Passw0rd");
        enableAndConfirmEmailOtp(session);

        String challengeToken = loginAndCaptureChallengeToken(
                "acme-eotp-verify.localhost", "eotp-verify@example.com", "Str0ng!Passw0rd");
        String code = extractOtpCodeFromLastMailLog();

        MvcResult result = mockMvc.perform(post("/api/mfa/challenge/email-otp")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaEmailOtpChallengeRequest(challengeToken, code))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.email").value("eotp-verify@example.com"))
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNotNull();
    }

    @Test
    void aWrongEmailOtpCodeDoesNotBurnTheChallengeAndACorrectRetrySucceeds() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-retry"));
        HttpSession session =
                registerVerifyAndLogin("acme-eotp-retry.localhost", "eotp-retry@example.com", "Str0ng!Passw0rd");
        enableAndConfirmEmailOtp(session);

        String challengeToken =
                loginAndCaptureChallengeToken("acme-eotp-retry.localhost", "eotp-retry@example.com", "Str0ng!Passw0rd");
        String correctCode = extractOtpCodeFromLastMailLog();

        mockMvc.perform(post("/api/mfa/challenge/email-otp")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new MfaEmailOtpChallengeRequest(challengeToken, wrongCodeFor(correctCode)))))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/mfa/challenge/email-otp")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new MfaEmailOtpChallengeRequest(challengeToken, correctCode))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"));
    }

    @Test
    void verifiesTheChallengeWithARecoveryCodeAndEstablishesASession() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-recovery"));
        HttpSession session = registerVerifyAndLogin(
                "acme-eotp-recovery.localhost", "eotp-recovery@example.com", "Str0ng!Passw0rd");
        EnrollmentResult enrollment = enableAndConfirmEmailOtp(session);

        String challengeToken = loginAndCaptureChallengeToken(
                "acme-eotp-recovery.localhost", "eotp-recovery@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/mfa/challenge/recovery-code")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaRecoveryCodeChallengeRequest(
                                challengeToken, enrollment.recoveryCodes().get(0)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.email").value("eotp-recovery@example.com"));
    }

    @Test
    void disablingRequiresTheCorrectCurrentPassword() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-disable-wrongpw"));
        HttpSession session = registerVerifyAndLogin(
                "acme-eotp-disable-wrongpw.localhost", "eotp-disable-wrongpw@example.com", "Str0ng!Passw0rd");
        enableAndConfirmEmailOtp(session);

        mockMvc.perform(post("/api/mfa/disable")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaDisableRequest("totally-wrong"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void disablingEmailOtpAndLoggingInAgainAuthenticatesDirectlyWithoutAChallenge() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-eotp-disable"));
        HttpSession session =
                registerVerifyAndLogin("acme-eotp-disable.localhost", "eotp-disable@example.com", "Str0ng!Passw0rd");
        enableAndConfirmEmailOtp(session);

        mockMvc.perform(post("/api/mfa/disable")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaDisableRequest("Str0ng!Passw0rd"))))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(host("acme-eotp-disable.localhost"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("eotp-disable@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.email").value("eotp-disable@example.com"));
    }

    /** Returns a well-formed 6-digit code guaranteed to differ from {@code correctCode}. */
    private static String wrongCodeFor(String correctCode) {
        return "000000".equals(correctCode) ? "111111" : "000000";
    }

    private String loginAndCaptureChallengeToken(String tenantSubdomain, String email, String password)
            throws Exception {
        MvcResult result = mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(host(tenantSubdomain))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(email, password))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("MFA_REQUIRED"))
                .andReturn();
        LoginResponse response =
                objectMapper.readValue(result.getResponse().getContentAsString(), LoginResponse.class);
        return response.challengeToken();
    }

    private EnrollmentResult enableAndConfirmEmailOtp(HttpSession session) throws Exception {
        mockMvc.perform(post("/api/mfa/email-otp/enable").with(csrf()).session((MockHttpSession) session))
                .andExpect(status().isOk());
        String code = extractOtpCodeFromLastMailLog();

        MvcResult confirmResult = mockMvc.perform(post("/api/mfa/email-otp/confirm")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaConfirmRequest(code))))
                .andExpect(status().isOk())
                .andReturn();
        MfaConfirmResponse confirmResponse =
                objectMapper.readValue(confirmResult.getResponse().getContentAsString(), MfaConfirmResponse.class);
        return new EnrollmentResult(confirmResponse.recoveryCodes());
    }

    private HttpSession registerVerifyAndLogin(String tenantSubdomain, String email, String password)
            throws Exception {
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

    private static org.springframework.test.web.servlet.request.RequestPostProcessor host(String tenantSubdomain) {
        return request -> {
            request.setServerName(tenantSubdomain);
            return request;
        };
    }

    private String extractTokenFromLastMailLog() {
        String message =
                mailAppender.list.get(mailAppender.list.size() - 1).getFormattedMessage();
        Matcher matcher = TOKEN_PATTERN.matcher(message);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private String extractOtpCodeFromLastMailLog() {
        String message =
                mailAppender.list.get(mailAppender.list.size() - 1).getFormattedMessage();
        Matcher matcher = OTP_CODE_PATTERN.matcher(message);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }
}
