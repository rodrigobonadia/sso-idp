package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.MfaMethod;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({
    EmailOtpCodeRepositoryAdapter.class,
    MfaChallengeRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class EmailOtpCodeRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private EmailOtpCodeRepositoryAdapter emailOtpCodeRepository;

    @Autowired
    private MfaChallengeRepositoryAdapter mfaChallengeRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private User user;

    @BeforeEach
    void setUp() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-email-otp-code-" + System.nanoTime()));
        tenantRepository.save(tenant);
        user = User.register(
                tenant.id(),
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$12$hash"));
        userRepository.save(user);
    }

    @Test
    void savesAndReloadsAnEnrollmentConfirmationCodeWithNoChallengeId() {
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(
                user.id(), EmailOtpCodeHash.of("$2a$12$somehash"), Instant.now(), Duration.ofMinutes(5));

        emailOtpCodeRepository.save(code);
        Optional<EmailOtpCode> reloaded =
                emailOtpCodeRepository.findLatestByUserIdAndPurpose(user.id(), EmailOtpPurpose.ENROLLMENT_CONFIRMATION);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().purpose()).isEqualTo(EmailOtpPurpose.ENROLLMENT_CONFIRMATION);
        assertThat(reloaded.get().mfaChallengeId()).isEmpty();
        assertThat(reloaded.get().failedAttempts()).isZero();
    }

    @Test
    void savesAndReloadsALoginChallengeCodeByItsChallengeId() {
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(),
                user.tenantId(),
                MfaMethod.EMAIL_OTP,
                TokenHash.of("hash-" + System.nanoTime()),
                Instant.now(),
                Duration.ofMinutes(5));
        mfaChallengeRepository.save(challenge);
        EmailOtpCode code = EmailOtpCode.issueForChallenge(
                user.id(), challenge.id(), EmailOtpCodeHash.of("$2a$12$somehash"), Instant.now(), Duration.ofMinutes(5));

        emailOtpCodeRepository.save(code);
        Optional<EmailOtpCode> reloaded = emailOtpCodeRepository.findByMfaChallengeId(challenge.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().purpose()).isEqualTo(EmailOtpPurpose.LOGIN_CHALLENGE);
        assertThat(reloaded.get().mfaChallengeId()).contains(challenge.id());
    }

    @Test
    void findByMfaChallengeIdIsEmptyWhenNoCodeMatches() {
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(),
                user.tenantId(),
                MfaMethod.EMAIL_OTP,
                TokenHash.of("hash-" + System.nanoTime()),
                Instant.now(),
                Duration.ofMinutes(5));
        mfaChallengeRepository.save(challenge);

        assertThat(emailOtpCodeRepository.findByMfaChallengeId(challenge.id())).isEmpty();
    }

    @Test
    void findLatestByUserIdAndPurposeReturnsTheMostRecentlyIssuedRow() {
        EmailOtpCode older = EmailOtpCode.issueForEnrollment(
                user.id(), EmailOtpCodeHash.of("$2a$12$olderhash"), Instant.now().minusSeconds(60), Duration.ofMinutes(5));
        emailOtpCodeRepository.save(older);
        EmailOtpCode newer = EmailOtpCode.issueForEnrollment(
                user.id(), EmailOtpCodeHash.of("$2a$12$newerhash"), Instant.now(), Duration.ofMinutes(5));
        emailOtpCodeRepository.save(newer);

        Optional<EmailOtpCode> latest =
                emailOtpCodeRepository.findLatestByUserIdAndPurpose(user.id(), EmailOtpPurpose.ENROLLMENT_CONFIRMATION);

        assertThat(latest).isPresent();
        assertThat(latest.get().codeHash()).isEqualTo(newer.codeHash());
    }

    @Test
    void deleteByUserIdAndPurposeRemovesOnlyRowsOfThatPurpose() {
        EmailOtpCode enrollmentCode = EmailOtpCode.issueForEnrollment(
                user.id(), EmailOtpCodeHash.of("$2a$12$enrollhash"), Instant.now(), Duration.ofMinutes(5));
        emailOtpCodeRepository.save(enrollmentCode);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(),
                user.tenantId(),
                MfaMethod.EMAIL_OTP,
                TokenHash.of("hash-" + System.nanoTime()),
                Instant.now(),
                Duration.ofMinutes(5));
        mfaChallengeRepository.save(challenge);
        EmailOtpCode challengeCode = EmailOtpCode.issueForChallenge(
                user.id(), challenge.id(), EmailOtpCodeHash.of("$2a$12$challengehash"), Instant.now(), Duration.ofMinutes(5));
        emailOtpCodeRepository.save(challengeCode);

        emailOtpCodeRepository.deleteByUserIdAndPurpose(user.id(), EmailOtpPurpose.ENROLLMENT_CONFIRMATION);

        assertThat(emailOtpCodeRepository.findLatestByUserIdAndPurpose(user.id(), EmailOtpPurpose.ENROLLMENT_CONFIRMATION))
                .isEmpty();
        assertThat(emailOtpCodeRepository.findByMfaChallengeId(challenge.id())).isPresent();
    }
}
