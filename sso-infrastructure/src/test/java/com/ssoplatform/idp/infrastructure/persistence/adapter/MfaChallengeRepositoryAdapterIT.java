package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

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
    MfaChallengeRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class MfaChallengeRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MfaChallengeRepositoryAdapter mfaChallengeRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private User user;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-mfa-challenge-" + System.nanoTime()));
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
    void savesAndReloadsAChallengeByItsHash() {
        TokenHash tokenHash = TokenHash.of("hash-" + System.nanoTime());
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), tenant.id(), MfaMethod.TOTP, tokenHash, Instant.now(), Duration.ofMinutes(5));

        mfaChallengeRepository.save(challenge);
        Optional<MfaChallenge> reloaded = mfaChallengeRepository.findByTokenHash(tokenHash);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().method()).isEqualTo(MfaMethod.TOTP);
        assertThat(reloaded.get().isConsumed()).isFalse();
    }

    @Test
    void savesAndReloadsAnEmailOtpChallengeWithItsMethodPreserved() {
        TokenHash tokenHash = TokenHash.of("hash-email-otp-" + System.nanoTime());
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), tenant.id(), MfaMethod.EMAIL_OTP, tokenHash, Instant.now(), Duration.ofMinutes(5));

        mfaChallengeRepository.save(challenge);
        Optional<MfaChallenge> reloaded = mfaChallengeRepository.findByTokenHash(tokenHash);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().method()).isEqualTo(MfaMethod.EMAIL_OTP);
    }

    @Test
    void findByTokenHashIsEmptyWhenNoChallengeMatches() {
        assertThat(mfaChallengeRepository.findByTokenHash(TokenHash.of("no-such-hash"))).isEmpty();
    }

    @Test
    void reloadsAConsumedChallengeWithItsConsumedAtPreserved() {
        TokenHash tokenHash = TokenHash.of("hash-consumed-" + System.nanoTime());
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), tenant.id(), MfaMethod.TOTP, tokenHash, Instant.now(), Duration.ofMinutes(5));
        challenge.consume(Instant.now());

        mfaChallengeRepository.save(challenge);
        Optional<MfaChallenge> reloaded = mfaChallengeRepository.findByTokenHash(tokenHash);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().isConsumed()).isTrue();
    }
}
