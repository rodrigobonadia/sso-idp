package com.ssoplatform.idp.application.usecase.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.DuplicateTenantSlugException;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CreateTenantUseCaseTest {

    @Mock
    private TenantRepository tenantRepository;

    private CreateTenantUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new CreateTenantUseCase(tenantRepository);
    }

    @Test
    void createsAndPersistsANewTenantWhenSlugIsAvailable() {
        when(tenantRepository.existsBySlug(TenantSlug.of("acme"))).thenReturn(false);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));

        CreateTenantResult result = useCase.execute(new CreateTenantCommand("Acme Corp", "acme"));

        assertThat(result.slug()).isEqualTo("acme");
        assertThat(result.name()).isEqualTo("Acme Corp");
        assertThat(result.tenantId()).isNotNull();
        verify(tenantRepository).save(any(Tenant.class));
    }

    @Test
    void rejectsCreationWhenSlugIsAlreadyTaken() {
        when(tenantRepository.existsBySlug(TenantSlug.of("acme"))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(new CreateTenantCommand("Acme Corp", "acme")))
                .isInstanceOf(DuplicateTenantSlugException.class);
    }
}
