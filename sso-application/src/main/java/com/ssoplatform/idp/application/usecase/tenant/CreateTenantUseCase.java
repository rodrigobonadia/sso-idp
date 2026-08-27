package com.ssoplatform.idp.application.usecase.tenant;

import com.ssoplatform.idp.application.exception.DuplicateTenantSlugException;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import java.util.Objects;

/**
 * Registers a new tenant on the platform.
 *
 * <p>Slug uniqueness is an invariant that spans the whole tenant collection, so it cannot be
 * enforced by the {@link Tenant} entity alone - it is this use case's job to check it against
 * the {@link TenantRepository} port before creating the entity.
 */
public class CreateTenantUseCase {

    private final TenantRepository tenantRepository;

    public CreateTenantUseCase(TenantRepository tenantRepository) {
        this.tenantRepository = Objects.requireNonNull(tenantRepository, "tenantRepository must not be null");
    }

    public CreateTenantResult execute(CreateTenantCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        TenantSlug slug = TenantSlug.of(command.slug());
        if (tenantRepository.existsBySlug(slug)) {
            throw new DuplicateTenantSlugException(slug.value());
        }

        Tenant tenant = Tenant.create(command.name(), slug);
        Tenant saved = tenantRepository.save(tenant);

        return new CreateTenantResult(saved.id().value(), saved.slug().value(), saved.name());
    }
}
