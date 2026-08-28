package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.OAuthClientStatus;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
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
@Import({OAuthClientRepositoryAdapter.class, TenantRepositoryAdapter.class, InfrastructureTestConfiguration.class})
@Testcontainers
class OAuthClientRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private OAuthClientRepositoryAdapter oauthClientRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        // oauth_clients.tenant_id has a foreign key to tenants(id).
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-oauth-clients-" + System.nanoTime()));
        tenantRepository.save(tenant);
    }

    private OAuthClient newClient(String clientIdValue) {
        return OAuthClient.register(
                tenant.id(),
                ClientId.of(clientIdValue),
                ClientSecretHash.of("hashed-secret"),
                "Acme Test App",
                Set.of(RedirectUri.of("https://app.example.com/callback")),
                Set.of("openid", "profile", "email"),
                Set.of(GrantType.AUTHORIZATION_CODE));
    }

    @Test
    void savesAndReloadsAClientByItsClientId() {
        ClientId clientId = ClientId.of("acme-app-" + System.nanoTime());
        OAuthClient client = newClient(clientId.value());

        oauthClientRepository.save(client);
        Optional<OAuthClient> reloaded = oauthClientRepository.findByClientId(clientId);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(client.id());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().clientId()).isEqualTo(clientId);
        assertThat(reloaded.get().name()).isEqualTo("Acme Test App");
        assertThat(reloaded.get().redirectUris())
                .containsExactly(RedirectUri.of("https://app.example.com/callback"));
        assertThat(reloaded.get().allowedScopes()).containsExactlyInAnyOrder("openid", "profile", "email");
        assertThat(reloaded.get().allowedGrantTypes()).containsExactly(GrantType.AUTHORIZATION_CODE);
        assertThat(reloaded.get().status()).isEqualTo(OAuthClientStatus.ACTIVE);
    }

    @Test
    void findByClientIdIsEmptyWhenNoClientMatches() {
        assertThat(oauthClientRepository.findByClientId(ClientId.of("no-such-client"))).isEmpty();
    }

    @Test
    void reloadsADisabledClientWithItsStatusPreserved() {
        ClientId clientId = ClientId.of("acme-disabled-app-" + System.nanoTime());
        OAuthClient client = newClient(clientId.value());
        client.disable();

        oauthClientRepository.save(client);
        Optional<OAuthClient> reloaded = oauthClientRepository.findByClientId(clientId);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(OAuthClientStatus.DISABLED);
        assertThat(reloaded.get().isUsable()).isFalse();
    }
}
