package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.resource.ClientResourceAuthorization;
import com.ssoplatform.idp.domain.resource.Resource;
import com.ssoplatform.idp.domain.resource.ResourceIdentifier;
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
@Import({
    ClientResourceAuthorizationRepositoryAdapter.class,
    OAuthClientRepositoryAdapter.class,
    ResourceRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class ClientResourceAuthorizationRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private ClientResourceAuthorizationRepositoryAdapter authorizationRepository;

    @Autowired
    private OAuthClientRepositoryAdapter oauthClientRepository;

    @Autowired
    private ResourceRepositoryAdapter resourceRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private Tenant tenant;
    private OAuthClient client;
    private Resource resource;

    @BeforeEach
    void setUp() {
        // client_resource_authorizations has foreign keys to tenants, oauth_clients and resources.
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-cra-" + System.nanoTime()));
        tenantRepository.save(tenant);

        client = OAuthClient.register(
                tenant.id(),
                ClientId.of("billing-service-" + System.nanoTime()),
                ClientSecretHash.of("hashed-secret"),
                "Billing Service",
                Set.of(RedirectUri.of("https://app.example.com/callback")),
                Set.of("openid"),
                Set.of(GrantType.CLIENT_CREDENTIALS));
        oauthClientRepository.save(client);

        resource = Resource.register(
                tenant.id(),
                ResourceIdentifier.of("https://api.example.com/orders-" + System.nanoTime()),
                "Orders API",
                Set.of("orders:read", "orders:write"));
        resourceRepository.save(resource);
    }

    @Test
    void savesAndReloadsAnAuthorizationByClientAndResource() {
        ClientResourceAuthorization authorization =
                ClientResourceAuthorization.authorize(tenant.id(), client.id(), resource.id(), Set.of("orders:read"));

        authorizationRepository.save(authorization);
        Optional<ClientResourceAuthorization> reloaded =
                authorizationRepository.findByOAuthClientIdAndResourceId(client.id(), resource.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(authorization.id());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().oauthClientId()).isEqualTo(client.id());
        assertThat(reloaded.get().resourceId()).isEqualTo(resource.id());
        assertThat(reloaded.get().grantedScopes()).containsExactly("orders:read");
    }

    @Test
    void findByOAuthClientIdAndResourceIdIsEmptyWhenNoAuthorizationMatches() {
        assertThat(authorizationRepository.findByOAuthClientIdAndResourceId(client.id(), resource.id())).isEmpty();
    }
}
