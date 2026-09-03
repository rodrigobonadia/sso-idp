package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredentialStatus;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
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
    EmailOtpCredentialRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class EmailOtpCredentialRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private EmailOtpCredentialRepositoryAdapter emailOtpCredentialRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private User user;

    @BeforeEach
    void setUp() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-email-otp-cred-" + System.nanoTime()));
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
    void savesAndReloadsAPendingCredentialByUserId() {
        EmailOtpCredential credential = EmailOtpCredential.enable(user.id(), Instant.now());

        emailOtpCredentialRepository.save(credential);
        Optional<EmailOtpCredential> reloaded = emailOtpCredentialRepository.findByUserId(user.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().status()).isEqualTo(EmailOtpCredentialStatus.PENDING_ACTIVATION);
        assertThat(reloaded.get().activatedAt()).isNull();
    }

    @Test
    void reloadsAnActivatedCredentialWithItsActivatedAtPreserved() {
        EmailOtpCredential credential = EmailOtpCredential.enable(user.id(), Instant.now());
        credential.activate(Instant.now());

        emailOtpCredentialRepository.save(credential);
        Optional<EmailOtpCredential> reloaded = emailOtpCredentialRepository.findByUserId(user.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(EmailOtpCredentialStatus.ACTIVE);
        assertThat(reloaded.get().activatedAt()).isNotNull();
    }

    @Test
    void findByUserIdIsEmptyWhenNoCredentialExists() {
        assertThat(emailOtpCredentialRepository.findByUserId(user.id())).isEmpty();
    }

    @Test
    void deleteByUserIdRemovesTheCredential() {
        EmailOtpCredential credential = EmailOtpCredential.enable(user.id(), Instant.now());
        emailOtpCredentialRepository.save(credential);

        emailOtpCredentialRepository.deleteByUserId(user.id());

        assertThat(emailOtpCredentialRepository.findByUserId(user.id())).isEmpty();
    }
}
