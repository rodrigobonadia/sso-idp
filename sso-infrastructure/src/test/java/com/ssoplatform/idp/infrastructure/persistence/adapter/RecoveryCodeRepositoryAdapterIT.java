package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
import java.time.Instant;
import java.util.List;
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
    RecoveryCodeRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class RecoveryCodeRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private RecoveryCodeRepositoryAdapter recoveryCodeRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private User user;

    @BeforeEach
    void setUp() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-recovery-" + System.nanoTime()));
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
    void savesABatchAndReloadsOnlyTheUnconsumedOnes() {
        RecoveryCode consumed =
                RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$consumedhash"), Instant.now());
        consumed.consume(Instant.now());
        RecoveryCode unconsumed =
                RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$unconsumedhash"), Instant.now());

        recoveryCodeRepository.saveAll(List.of(consumed, unconsumed));
        List<RecoveryCode> reloaded = recoveryCodeRepository.findUnconsumedByUserId(user.id());

        assertThat(reloaded).hasSize(1);
        assertThat(reloaded.get(0).codeHash()).isEqualTo(unconsumed.codeHash());
    }

    @Test
    void findUnconsumedByUserIdIsEmptyWhenNoCodesExist() {
        assertThat(recoveryCodeRepository.findUnconsumedByUserId(user.id())).isEmpty();
    }

    @Test
    void deleteAllByUserIdRemovesEveryCodeRegardlessOfConsumptionState() {
        RecoveryCode consumed =
                RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$consumedhash"), Instant.now());
        consumed.consume(Instant.now());
        RecoveryCode unconsumed =
                RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$unconsumedhash"), Instant.now());
        recoveryCodeRepository.saveAll(List.of(consumed, unconsumed));

        recoveryCodeRepository.deleteAllByUserId(user.id());

        assertThat(recoveryCodeRepository.findUnconsumedByUserId(user.id())).isEmpty();
    }

    @Test
    void saveReloadsASingleConsumedCodeUpdate() {
        RecoveryCode code = RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$onehash"), Instant.now());
        recoveryCodeRepository.saveAll(List.of(code));
        assertThat(recoveryCodeRepository.findUnconsumedByUserId(user.id())).hasSize(1);

        code.consume(Instant.now());
        recoveryCodeRepository.save(code);

        assertThat(recoveryCodeRepository.findUnconsumedByUserId(user.id())).isEmpty();
    }
}
