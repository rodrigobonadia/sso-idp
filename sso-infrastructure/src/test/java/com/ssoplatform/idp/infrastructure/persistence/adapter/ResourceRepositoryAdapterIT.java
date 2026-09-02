package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.resource.Resource;
import com.ssoplatform.idp.domain.resource.ResourceIdentifier;
import com.ssoplatform.idp.domain.resource.ResourceStatus;
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
@Import({ResourceRepositoryAdapter.class, TenantRepositoryAdapter.class, InfrastructureTestConfiguration.class})
@Testcontainers
class ResourceRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private ResourceRepositoryAdapter resourceRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        // resources.tenant_id has a foreign key to tenants(id).
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-resources-" + System.nanoTime()));
        tenantRepository.save(tenant);
    }

    private Resource newResource(String identifierValue) {
        return Resource.register(
                tenant.id(),
                ResourceIdentifier.of(identifierValue),
                "Orders API",
                Set.of("orders:read", "orders:write"));
    }

    @Test
    void savesAndReloadsAResourceByTenantIdAndIdentifier() {
        ResourceIdentifier identifier = ResourceIdentifier.of("https://api.example.com/orders-" + System.nanoTime());
        Resource resource = newResource(identifier.value());

        resourceRepository.save(resource);
        Optional<Resource> reloaded = resourceRepository.findByTenantIdAndIdentifier(tenant.id(), identifier);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(resource.id());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().identifier()).isEqualTo(identifier);
        assertThat(reloaded.get().name()).isEqualTo("Orders API");
        assertThat(reloaded.get().scopes()).containsExactlyInAnyOrder("orders:read", "orders:write");
        assertThat(reloaded.get().status()).isEqualTo(ResourceStatus.ACTIVE);
    }

    @Test
    void findByTenantIdAndIdentifierIsEmptyWhenNoResourceMatches() {
        assertThat(resourceRepository.findByTenantIdAndIdentifier(
                        tenant.id(), ResourceIdentifier.of("https://api.example.com/no-such-resource")))
                .isEmpty();
    }

    @Test
    void reloadsADisabledResourceWithItsStatusPreserved() {
        ResourceIdentifier identifier =
                ResourceIdentifier.of("https://api.example.com/orders-disabled-" + System.nanoTime());
        Resource resource = newResource(identifier.value());
        resource.disable();

        resourceRepository.save(resource);
        Optional<Resource> reloaded = resourceRepository.findByTenantIdAndIdentifier(tenant.id(), identifier);

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(ResourceStatus.DISABLED);
        assertThat(reloaded.get().isUsable()).isFalse();
    }
}
