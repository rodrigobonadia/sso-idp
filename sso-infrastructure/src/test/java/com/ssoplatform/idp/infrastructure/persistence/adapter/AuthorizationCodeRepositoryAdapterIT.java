package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.authorization.CodeChallenge;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
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
    AuthorizationCodeRepositoryAdapter.class,
    OAuthClientRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class AuthorizationCodeRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private AuthorizationCodeRepositoryAdapter authorizationCodeRepository;

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
        // authorization_codes has NOT NULL foreign keys to tenants, oauth_clients and users, so
        // every test needs all three persisted first.
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-authz-codes-" + System.nanoTime()));
        tenantRepository.save(tenant);

        client = OAuthClient.register(
                tenant.id(),
                ClientId.of("acme-app-" + System.nanoTime()),
                ClientSecretHash.of("hashed-secret"),
                "Acme Test App",
                Set.of(RedirectUri.of("https://app.example.com/callback")),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE));
        oauthClientRepository.save(client);

        user = User.register(
                tenant.id(),
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$12$hash"));
        userRepository.save(user);
    }

    private AuthorizationCode newCode() {
        return newCode(null);
    }

    private AuthorizationCode newCode(String nonce) {
        return AuthorizationCode.issue(
                tenant.id(),
                client.id(),
                user.id(),
                TokenHash.of("hash-" + System.nanoTime()),
                RedirectUri.of("https://app.example.com/callback"),
                Set.of("openid", "profile"),
                CodeChallenge.of("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                nonce,
                Instant.now(),
                Duration.ofMinutes(5));
    }

    @Test
    void savesAndReloadsACodeByItsHash() {
        AuthorizationCode code = newCode();

        authorizationCodeRepository.save(code);
        Optional<AuthorizationCode> reloaded = authorizationCodeRepository.findByCodeHash(code.codeHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(code.id());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().oauthClientId()).isEqualTo(client.id());
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().redirectUri()).isEqualTo(RedirectUri.of("https://app.example.com/callback"));
        assertThat(reloaded.get().scopes()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(reloaded.get().codeChallenge())
                .isEqualTo(CodeChallenge.of("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assertThat(reloaded.get().nonce()).isNull();
        assertThat(reloaded.get().isConsumed()).isFalse();
    }

    @Test
    void savesAndReloadsACodeWithANonce() {
        AuthorizationCode code = newCode("round-trip-nonce");

        authorizationCodeRepository.save(code);
        Optional<AuthorizationCode> reloaded = authorizationCodeRepository.findByCodeHash(code.codeHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().nonce()).isEqualTo("round-trip-nonce");
    }

    @Test
    void findByCodeHashIsEmptyWhenNoCodeMatches() {
        assertThat(authorizationCodeRepository.findByCodeHash(TokenHash.of("no-such-hash"))).isEmpty();
    }

    @Test
    void reloadsAConsumedCodeWithItsConsumedAtPreserved() {
        AuthorizationCode code = newCode();
        Instant consumedAt = Instant.now().plusSeconds(10);
        code.consume(consumedAt);

        authorizationCodeRepository.save(code);
        Optional<AuthorizationCode> reloaded = authorizationCodeRepository.findByCodeHash(code.codeHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().isConsumed()).isTrue();
    }
}
