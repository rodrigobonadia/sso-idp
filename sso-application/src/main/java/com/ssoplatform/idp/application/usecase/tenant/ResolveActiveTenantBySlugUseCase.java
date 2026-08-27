package com.ssoplatform.idp.application.usecase.tenant;

import com.ssoplatform.idp.application.exception.TenantNotActiveException;
import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import java.util.Objects;

/**
 * Resolves a tenant by its slug for callers that only have the slug in hand - chiefly, the web
 * layer's subdomain-based tenant resolution (e.g. {@code acme.ssoplatform.example}) - and need to
 * confirm the tenant both exists and is currently active before letting a request proceed under
 * it. A slug that resolves to a suspended tenant is treated the same as one that doesn't exist at
 * all from the caller's point of view: either way, no request should be allowed to proceed as
 * that tenant.
 */
public class ResolveActiveTenantBySlugUseCase {

    private final TenantRepository tenantRepository;

    public ResolveActiveTenantBySlugUseCase(TenantRepository tenantRepository) {
        this.tenantRepository = Objects.requireNonNull(tenantRepository, "tenantRepository must not be null");
    }

    public TenantSummary execute(String slugValue) {
        Objects.requireNonNull(slugValue, "slugValue must not be null");

        TenantSlug slug = TenantSlug.of(slugValue);
        Tenant tenant = tenantRepository.findBySlug(slug).orElseThrow(() -> new TenantNotFoundException(slugValue));
        if (!tenant.isActive()) {
            throw new TenantNotActiveException(tenant.slug().value());
        }

        return new TenantSummary(tenant.id().value(), tenant.slug().value(), tenant.name());
    }
}
