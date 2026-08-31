package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenStatus;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
    RefreshTokenRepositoryAdapter.class,
    OAuthClientRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class RefreshTokenRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private RefreshTokenRepositoryAdapter refreshTokenRepository;

    @Autowired
    private OAuthClientRepositoryAdapter oauthClientRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    private Tenant tenant;
    private OAuthClient client;
    private User user;

    @BeforeEach
    void setUp() {
        // refresh_tokens has NOT NULL foreign keys to tenants, oauth_clients and users, so every
        // test needs all three persisted first.
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-refresh-tokens-" + System.nanoTime()));
        tenantRepository.save(tenant);

        client = OAuthClient.register(
                tenant.id(),
                ClientId.of("acme-app-" + System.nanoTime()),
                ClientSecretHash.of("hashed-secret"),
                "Acme Test App",
                Set.of(RedirectUri.of("https://app.example.com/callback")),
                Set.of("openid", "profile", "offline_access"),
                Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
        oauthClientRepository.save(client);

        user = User.register(tenant.id(), Email.of("someone@example.com"), HashedPassword.of("$2a$12$hash"));
        userRepository.save(user);
    }

    private RefreshToken newFirstToken() {
        return RefreshToken.issueFirst(
                tenant.id(),
                client.id(),
                user.id(),
                TokenHash.of("hash-" + System.nanoTime()),
                Set.of("openid", "offline_access"),
                Instant.now(),
                Duration.ofDays(30));
    }

    @Test
    void savesAndReloadsAFirstTokenByItsHash() {
        RefreshToken token = newFirstToken();

        refreshTokenRepository.save(token);
        Optional<RefreshToken> reloaded = refreshTokenRepository.findByTokenHash(token.tokenHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(token.id());
        assertThat(reloaded.get().familyId()).isEqualTo(token.familyId());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().oauthClientId()).isEqualTo(client.id());
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().scopes()).containsExactlyInAnyOrder("openid", "offline_access");
        assertThat(reloaded.get().status()).isEqualTo(RefreshTokenStatus.ACTIVE);
        assertThat(reloaded.get().familyExpiresAt()).isEqualTo(token.familyExpiresAt());
    }

    @Test
    void findByTokenHashIsEmptyWhenNoTokenMatches() {
        assertThat(refreshTokenRepository.findByTokenHash(TokenHash.of("no-such-hash"))).isEmpty();
    }

    @Test
    void reloadsARotatedTokenWithItsStatusPreserved() {
        RefreshToken token = newFirstToken();
        token.rotate(Instant.now());

        refreshTokenRepository.save(token);
        Optional<RefreshToken> reloaded = refreshTokenRepository.findByTokenHash(token.tokenHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(RefreshTokenStatus.ROTATED);
    }

    @Test
    void reloadsARevokedTokenWithItsStatusPreserved() {
        RefreshToken token = newFirstToken();
        token.revoke();

        refreshTokenRepository.save(token);
        Optional<RefreshToken> reloaded = refreshTokenRepository.findByTokenHash(token.tokenHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(RefreshTokenStatus.REVOKED);
    }

    @Test
    void findAllByFamilyIdReturnsEveryTokenInTheRotationChain() {
        RefreshToken first = newFirstToken();
        refreshTokenRepository.save(first);
        RefreshToken second =
                RefreshToken.continueFamily(first, TokenHash.of("hash-second-" + System.nanoTime()), Instant.now());
        refreshTokenRepository.save(second);

        List<RefreshToken> family = refreshTokenRepository.findAllByFamilyId(first.familyId());

        assertThat(family).hasSize(2);
        assertThat(family).extracting(RefreshToken::id).containsExactlyInAnyOrder(first.id(), second.id());
    }

    @Test
    void findAllByFamilyIdIsEmptyWhenNoTokenMatches() {
        RefreshToken first = newFirstToken();

        assertThat(refreshTokenRepository.findAllByFamilyId(first.familyId())).isEmpty();
    }
}
