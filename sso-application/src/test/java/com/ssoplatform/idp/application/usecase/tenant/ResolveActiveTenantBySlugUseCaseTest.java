package com.ssoplatform.idp.application.usecase.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.TenantNotActiveException;
import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ResolveActiveTenantBySlugUseCaseTest {

    @Mock
    private TenantRepository tenantRepository;

    private ResolveActiveTenantBySlugUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new ResolveActiveTenantBySlugUseCase(tenantRepository);
    }

    @Test
    void resolvesAnActiveTenantBySlug() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme"));
        when(tenantRepository.findBySlug(TenantSlug.of("acme"))).thenReturn(Optional.of(tenant));

        TenantSummary result = useCase.execute("acme");

        assertThat(result.tenantId()).isEqualTo(tenant.id().value());
        assertThat(result.slug()).isEqualTo("acme");
        assertThat(result.name()).isEqualTo("Acme Corp");
    }

    @Test
    void rejectsWhenNoTenantHasThatSlug() {
        when(tenantRepository.findBySlug(TenantSlug.of("ghost"))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute("ghost")).isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void rejectsWhenTheTenantIsSuspended() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme"));
        tenant.suspend();
        when(tenantRepository.findBySlug(TenantSlug.of("acme"))).thenReturn(Optional.of(tenant));

        assertThatThrownBy(() -> useCase.execute("acme")).isInstanceOf(TenantNotActiveException.class);
    }
}
