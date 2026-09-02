package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
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
    PasswordResetTokenRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class PasswordResetTokenRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private PasswordResetTokenRepositoryAdapter passwordResetTokenRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private User user;

    @BeforeEach
    void setUp() {
        // password_reset_tokens.user_id has a foreign key to users(id), which in turn needs a tenant.
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-reset-tokens-" + System.nanoTime()));
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
    void savesAndReloadsATokenByItsHash() {
        TokenHash tokenHash = TokenHash.of("hash-" + System.nanoTime());
        PasswordResetToken token =
                PasswordResetToken.issue(user.id(), tokenHash, Instant.now(), Duration.ofHours(1));

        passwordResetTokenRepository.save(token);
        Optional<PasswordResetToken> reloaded = passwordResetTokenRepository.findByTokenHash(tokenHash);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().tokenHash()).isEqualTo(tokenHash);
        assertThat(reloaded.get().isConsumed()).isFalse();
    }

    @Test
    void findByTokenHashIsEmptyWhenNoTokenMatches() {
        assertThat(passwordResetTokenRepository.findByTokenHash(TokenHash.of("no-such-hash")))
                .isEmpty();
    }

    @Test
    void reloadsAConsumedTokenWithItsConsumedAtPreserved() {
        TokenHash tokenHash = TokenHash.of("hash-consumed-" + System.nanoTime());
        PasswordResetToken token =
                PasswordResetToken.issue(user.id(), tokenHash, Instant.now(), Duration.ofHours(1));
        token.consume(Instant.now());

        passwordResetTokenRepository.save(token);
        Optional<PasswordResetToken> reloaded = passwordResetTokenRepository.findByTokenHash(tokenHash);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().isConsumed()).isTrue();
    }
}
