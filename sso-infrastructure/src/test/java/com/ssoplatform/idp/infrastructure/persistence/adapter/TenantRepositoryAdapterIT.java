package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration test exercising the adapter against a real PostgreSQL instance (via Testcontainers)
 * with Flyway migrations applied, rather than against mocks - this is what actually proves the
 * mapping and SQL constraints are correct.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({TenantRepositoryAdapter.class, InfrastructureTestConfiguration.class})
@Testcontainers
class TenantRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    @Test
    void savesAndReloadsATenantById() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme"));

        tenantRepository.save(tenant);
        Optional<Tenant> reloaded = tenantRepository.findById(tenant.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(tenant.id());
        assertThat(reloaded.get().slug()).isEqualTo(tenant.slug());
        assertThat(reloaded.get().name()).isEqualTo(tenant.name());
        assertThat(reloaded.get().status()).isEqualTo(tenant.status());
    }

    @Test
    void findByIdReturnsEmptyWhenTenantDoesNotExist() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("ghost"));

        assertThat(tenantRepository.findById(tenant.id())).isEmpty();
    }

    @Test
    void findBySlugLocatesAPersistedTenant() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-slug-lookup"));
        tenantRepository.save(tenant);

        assertThat(tenantRepository.findBySlug(TenantSlug.of("acme-slug-lookup")))
                .isPresent()
                .get()
                .extracting(Tenant::id)
                .isEqualTo(tenant.id());
    }

    @Test
    void existsBySlugReflectsPersistedTenants() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-exists-check"));
        tenantRepository.save(tenant);

        assertThat(tenantRepository.existsBySlug(TenantSlug.of("acme-exists-check"))).isTrue();
        assertThat(tenantRepository.existsBySlug(TenantSlug.of("definitely-not-registered"))).isFalse();
    }

    @Test
    void reloadsASuspendedTenantWithItsStatusPreserved() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-suspended"));
        tenant.suspend();

        tenantRepository.save(tenant);
        Optional<Tenant> reloaded = tenantRepository.findById(tenant.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().isActive()).isFalse();
    }
}
