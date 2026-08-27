package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.infrastructure.persistence.entity.TenantJpaEntity;

/** Translates between the {@link Tenant} domain entity and its JPA row representation. */
public final class TenantEntityMapper {

    private TenantEntityMapper() {}

    public static TenantJpaEntity toEntity(Tenant tenant) {
        return new TenantJpaEntity(
                tenant.id().value(),
                tenant.slug().value(),
                tenant.name(),
                tenant.status(),
                tenant.createdAt());
    }

    public static Tenant toDomain(TenantJpaEntity entity) {
        return Tenant.reconstitute(
                TenantId.of(entity.getId()),
                TenantSlug.of(entity.getSlug()),
                entity.getName(),
                entity.getStatus(),
                entity.getCreatedAt());
    }
}
