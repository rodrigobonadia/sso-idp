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
import java.nio.ByteBuffer;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
 * Exercises the complete Phase 4.1 TOTP MFA flow end-to-end: real Spring context, real Postgres
 * via Testcontainers, and a real RFC 6238 code computed independently in this test (against the
 * exact secret {@code POST /api/mfa/totp/enroll} returns) rather than reusing {@code
 * HmacSha1TotpCodeVerifierAdapter} itself - proving the production algorithm from the outside, the
 * same way a real authenticator app would, instead of testing the implementation against itself.
 * Every exception-path edge case already has dedicated unit-test coverage at the use-case level
 * (see {@code sso-application}'s {@code usecase.mfa} package) - this class instead proves what
 * only a real end-to-end run can: controller wiring, {@code SecurityConfig}'s permissions for the
 * two-step login split, and the real interaction between enrollment, a subsequent password-based
 * login, and the MFA challenge round trip.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class MfaApiControllerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    private static final Pattern TOKEN_PATTERN = Pattern.compile("token=([A-Za-z0-9_-]+)");
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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

    private record EnrollmentResult(byte[] secret, List<String> recoveryCodes) {}

    @Test
    void enrollingReturnsABase32SecretAndAnOtpauthUriContainingIt() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-enroll"));
        HttpSession session =
                registerVerifyAndLogin("acme-mfa-enroll.localhost", "mfa-enroll@example.com", "Str0ng!Passw0rd");

        MvcResult result = mockMvc.perform(
                        post("/api/mfa/totp/enroll").with(csrf()).session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secretBase32").isNotEmpty())
                .andExpect(jsonPath("$.otpauthUri", org.hamcrest.Matchers.startsWith("otpauth://totp/")))
                .andReturn();
        MfaEnrollResponse response =
                objectMapper.readValue(result.getResponse().getContentAsString(), MfaEnrollResponse.class);
        assertThat(response.otpauthUri()).contains(response.secretBase32());
    }

    @Test
    void confirmingWithACorrectCodeActivatesMfaAndReturnsTenRecoveryCodes() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-confirm"));
        HttpSession session =
                registerVerifyAndLogin("acme-mfa-confirm.localhost", "mfa-confirm@example.com", "Str0ng!Passw0rd");

        EnrollmentResult enrollment = enrollAndConfirmTotp(session);

        assertThat(enrollment.recoveryCodes()).hasSize(10);
        assertThat(enrollment.recoveryCodes())
                .allMatch(code -> code.matches("[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}"));
    }

    @Test
    void confirmingWithAWrongCodeIsRejectedAndAGenuineRetryStillSucceeds() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-wrongconfirm"));
        HttpSession session = registerVerifyAndLogin(
                "acme-mfa-wrongconfirm.localhost", "mfa-wrongconfirm@example.com", "Str0ng!Passw0rd");

        MvcResult enrollResult = mockMvc.perform(
                        post("/api/mfa/totp/enroll").with(csrf()).session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn();
        MfaEnrollResponse enrollResponse =
                objectMapper.readValue(enrollResult.getResponse().getContentAsString(), MfaEnrollResponse.class);
        byte[] secret = base32Decode(enrollResponse.secretBase32());

        // A wrong TOTP code at confirmation time is InvalidMfaCodeException (401), not a
        // request-shape problem - TotpCode.of("000000") is itself perfectly well-formed.
        mockMvc.perform(post("/api/mfa/totp/confirm")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaConfirmRequest("000000"))))
                .andExpect(status().isUnauthorized());

        // The pending enrollment survives a wrong attempt - a genuine retry with the correct code
        // against the SAME still-pending secret must still succeed rather than needing to
        // re-enroll from scratch.
        mockMvc.perform(post("/api/mfa/totp/confirm")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaConfirmRequest(currentTotpCode(secret)))))
                .andExpect(status().isOk());
    }

    @Test
    void loginIssuesAnMfaChallengeInsteadOfASessionOnceMfaIsActive() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-challenge"));
        HttpSession session = registerVerifyAndLogin(
                "acme-mfa-challenge.localhost", "mfa-challenge@example.com", "Str0ng!Passw0rd");
        enrollAndConfirmTotp(session);

        MvcResult loginResult = mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(host("acme-mfa-challenge.localhost"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("mfa-challenge@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("MFA_REQUIRED"))
                .andExpect(jsonPath("$.challengeToken").isNotEmpty())
                .andReturn();

        // No session was established by a challenge-only login.
        assertThat(loginResult.getRequest().getSession(false)).isNull();
    }

    @Test
    void verifiesTheChallengeWithACorrectTotpCodeAndEstablishesASession() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-verify"));
        HttpSession session =
                registerVerifyAndLogin("acme-mfa-verify.localhost", "mfa-verify@example.com", "Str0ng!Passw0rd");
        EnrollmentResult enrollment = enrollAndConfirmTotp(session);

        String challengeToken =
                loginAndCaptureChallengeToken("acme-mfa-verify.localhost", "mfa-verify@example.com", "Str0ng!Passw0rd");

        MvcResult result = mockMvc.perform(post("/api/mfa/challenge/totp")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new MfaTotpChallengeRequest(challengeToken, currentTotpCode(enrollment.secret())))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.email").value("mfa-verify@example.com"))
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNotNull();
    }

    @Test
    void aWrongTotpCodeDoesNotBurnTheChallengeAndACorrectRetrySucceeds() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-retry"));
        HttpSession session =
                registerVerifyAndLogin("acme-mfa-retry.localhost", "mfa-retry@example.com", "Str0ng!Passw0rd");
        EnrollmentResult enrollment = enrollAndConfirmTotp(session);

        String challengeToken =
                loginAndCaptureChallengeToken("acme-mfa-retry.localhost", "mfa-retry@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/mfa/challenge/totp")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaTotpChallengeRequest(challengeToken, "000000"))))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/mfa/challenge/totp")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new MfaTotpChallengeRequest(challengeToken, currentTotpCode(enrollment.secret())))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"));
    }

    @Test
    void verifiesTheChallengeWithARecoveryCodeAndEstablishesASession() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-recovery"));
        HttpSession session =
                registerVerifyAndLogin("acme-mfa-recovery.localhost", "mfa-recovery@example.com", "Str0ng!Passw0rd");
        EnrollmentResult enrollment = enrollAndConfirmTotp(session);

        String challengeToken = loginAndCaptureChallengeToken(
                "acme-mfa-recovery.localhost", "mfa-recovery@example.com", "Str0ng!Passw0rd");

        mockMvc.perform(post("/api/mfa/challenge/recovery-code")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaRecoveryCodeChallengeRequest(
                                challengeToken, enrollment.recoveryCodes().get(0)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.email").value("mfa-recovery@example.com"));
    }

    @Test
    void aRecoveryCodeCannotBeReusedAfterItHasBeenConsumed() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-recovery-reuse"));
        HttpSession session = registerVerifyAndLogin(
                "acme-mfa-recovery-reuse.localhost", "mfa-recovery-reuse@example.com", "Str0ng!Passw0rd");
        EnrollmentResult enrollment = enrollAndConfirmTotp(session);
        String usedRecoveryCode = enrollment.recoveryCodes().get(0);

        String firstChallenge = loginAndCaptureChallengeToken(
                "acme-mfa-recovery-reuse.localhost", "mfa-recovery-reuse@example.com", "Str0ng!Passw0rd");
        mockMvc.perform(post("/api/mfa/challenge/recovery-code")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new MfaRecoveryCodeChallengeRequest(firstChallenge, usedRecoveryCode))))
                .andExpect(status().isOk());

        String secondChallenge = loginAndCaptureChallengeToken(
                "acme-mfa-recovery-reuse.localhost", "mfa-recovery-reuse@example.com", "Str0ng!Passw0rd");
        mockMvc.perform(post("/api/mfa/challenge/recovery-code")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new MfaRecoveryCodeChallengeRequest(secondChallenge, usedRecoveryCode))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void disablingRequiresTheCorrectCurrentPassword() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-disable-wrongpw"));
        HttpSession session = registerVerifyAndLogin(
                "acme-mfa-disable-wrongpw.localhost", "mfa-disable-wrongpw@example.com", "Str0ng!Passw0rd");
        enrollAndConfirmTotp(session);

        mockMvc.perform(post("/api/mfa/disable")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaDisableRequest("totally-wrong"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void disablingMfaAndLoggingInAgainAuthenticatesDirectlyWithoutAChallenge() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-mfa-disable"));
        HttpSession session =
                registerVerifyAndLogin("acme-mfa-disable.localhost", "mfa-disable@example.com", "Str0ng!Passw0rd");
        enrollAndConfirmTotp(session);

        mockMvc.perform(post("/api/mfa/disable")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaDisableRequest("Str0ng!Passw0rd"))))
                .andExpect(status().isNoContent());

        mockMvc.perform(post("/api/login")
                        .with(csrf())
                        .with(host("acme-mfa-disable.localhost"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("mfa-disable@example.com", "Str0ng!Passw0rd"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("AUTHENTICATED"))
                .andExpect(jsonPath("$.email").value("mfa-disable@example.com"));
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

    private EnrollmentResult enrollAndConfirmTotp(HttpSession session) throws Exception {
        MvcResult enrollResult = mockMvc.perform(
                        post("/api/mfa/totp/enroll").with(csrf()).session((MockHttpSession) session))
                .andExpect(status().isOk())
                .andReturn();
        MfaEnrollResponse enrollResponse =
                objectMapper.readValue(enrollResult.getResponse().getContentAsString(), MfaEnrollResponse.class);
        byte[] secret = base32Decode(enrollResponse.secretBase32());

        MvcResult confirmResult = mockMvc.perform(post("/api/mfa/totp/confirm")
                        .with(csrf())
                        .session((MockHttpSession) session)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new MfaConfirmRequest(currentTotpCode(secret)))))
                .andExpect(status().isOk())
                .andReturn();
        MfaConfirmResponse confirmResponse =
                objectMapper.readValue(confirmResult.getResponse().getContentAsString(), MfaConfirmResponse.class);
        return new EnrollmentResult(secret, confirmResponse.recoveryCodes());
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

    private static byte[] base32Decode(String base32) {
        StringBuilder bits = new StringBuilder();
        for (char c : base32.toUpperCase().toCharArray()) {
            int idx = BASE32_ALPHABET.indexOf(c);
            if (idx < 0) {
                continue;
            }
            String fiveBits = Integer.toBinaryString(idx);
            while (fiveBits.length() < 5) {
                fiveBits = "0" + fiveBits;
            }
            bits.append(fiveBits);
        }
        int byteCount = bits.length() / 8;
        byte[] result = new byte[byteCount];
        for (int i = 0; i < byteCount; i++) {
            result[i] = (byte) Integer.parseInt(bits.substring(i * 8, i * 8 + 8), 2);
        }
        return result;
    }

    /**
     * Computes a real RFC 6238 TOTP code independently of {@code HmacSha1TotpCodeVerifierAdapter}
     * - reimplemented here deliberately (that method is package-private and this test's package
     * cannot see it anyway) so this test proves the production algorithm from the outside, exactly
     * as a real authenticator app would, instead of testing the implementation against itself.
     */
    private static String currentTotpCode(byte[] secret) throws Exception {
        long timeStep = (System.currentTimeMillis() / 1000L) / 30;
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(timeStep).array();
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret, "HmacSHA1"));
        byte[] hash = mac.doFinal(counterBytes);
        int offset = hash[hash.length - 1] & 0x0F;
        int binaryCode = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        int truncated = binaryCode % 1_000_000;
        return String.format("%06d", truncated);
    }
}
