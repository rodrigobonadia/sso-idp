package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.mfa.TotpCredentialStatus;
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
    TotpCredentialRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class TotpCredentialRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private TotpCredentialRepositoryAdapter totpCredentialRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private User user;

    @BeforeEach
    void setUp() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-totp-" + System.nanoTime()));
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
        TotpCredential credential =
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now());

        totpCredentialRepository.save(credential);
        Optional<TotpCredential> reloaded = totpCredentialRepository.findByUserId(user.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().status()).isEqualTo(TotpCredentialStatus.PENDING_ACTIVATION);
        assertThat(reloaded.get().activatedAt()).isNull();
    }

    @Test
    void reloadsAnActivatedCredentialWithItsActivatedAtPreserved() {
        TotpCredential credential =
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now());
        credential.activate(Instant.now());

        totpCredentialRepository.save(credential);
        Optional<TotpCredential> reloaded = totpCredentialRepository.findByUserId(user.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(TotpCredentialStatus.ACTIVE);
        assertThat(reloaded.get().activatedAt()).isNotNull();
    }

    @Test
    void findByUserIdIsEmptyWhenNoCredentialExists() {
        assertThat(totpCredentialRepository.findByUserId(user.id())).isEmpty();
    }

    @Test
    void deleteByUserIdRemovesTheCredential() {
        TotpCredential credential =
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now());
        totpCredentialRepository.save(credential);

        totpCredentialRepository.deleteByUserId(user.id());

        assertThat(totpCredentialRepository.findByUserId(user.id())).isEmpty();
    }
}
