package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
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
@Import({UserRepositoryAdapter.class, TenantRepositoryAdapter.class, InfrastructureTestConfiguration.class})
@Testcontainers
class UserRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private UserRepositoryAdapter userRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        // users.tenant_id has a foreign key to tenants(id), so every test needs a persisted tenant first.
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-users-" + System.nanoTime()));
        tenantRepository.save(tenant);
    }

    @Test
    void savesAndReloadsAUserById() {
        User user = User.register(
                tenant.id(),
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$12$hash"));

        userRepository.save(user);
        Optional<User> reloaded = userRepository.findById(user.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().email()).isEqualTo(user.email());
        assertThat(reloaded.get().givenName()).isEqualTo(user.givenName());
        assertThat(reloaded.get().familyName()).isEqualTo(user.familyName());
        assertThat(reloaded.get().status()).isEqualTo(user.status());
        assertThat(reloaded.get().failedLoginAttempts()).isZero();
    }

    @Test
    void findByTenantIdAndEmailLocatesAPersistedUser() {
        User user = User.register(
                tenant.id(),
                Email.of("findme@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$12$hash"));
        userRepository.save(user);

        assertThat(userRepository.findByTenantIdAndEmail(tenant.id(), Email.of("findme@example.com")))
                .isPresent()
                .get()
                .extracting(User::id)
                .isEqualTo(user.id());
    }

    @Test
    void existsByTenantIdAndEmailIsFalseForAnotherTenantWithTheSameEmail() {
        User user = User.register(
                tenant.id(),
                Email.of("scoped@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$12$hash"));
        userRepository.save(user);

        Tenant otherTenant = Tenant.create("Other Corp", TenantSlug.of("other-corp-" + System.nanoTime()));
        tenantRepository.save(otherTenant);

        assertThat(userRepository.existsByTenantIdAndEmail(tenant.id(), Email.of("scoped@example.com")))
                .isTrue();
        assertThat(userRepository.existsByTenantIdAndEmail(otherTenant.id(), Email.of("scoped@example.com")))
                .isFalse();
    }

    @Test
    void reloadsALockedUserWithItsFailedAttemptsPreserved() {
        User user = User.register(
                tenant.id(),
                Email.of("locked@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$12$hash"));
        user.verifyEmail();
        for (int i = 0; i < User.MAX_FAILED_LOGIN_ATTEMPTS; i++) {
            user.recordFailedLogin();
        }

        userRepository.save(user);
        Optional<User> reloaded = userRepository.findById(user.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status().name()).isEqualTo("LOCKED");
        assertThat(reloaded.get().failedLoginAttempts()).isEqualTo(User.MAX_FAILED_LOGIN_ATTEMPTS);
    }
}
