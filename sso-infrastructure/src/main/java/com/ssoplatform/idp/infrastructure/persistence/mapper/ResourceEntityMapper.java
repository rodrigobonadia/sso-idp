package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.resource.Resource;
import com.ssoplatform.idp.domain.resource.ResourceId;
import com.ssoplatform.idp.domain.resource.ResourceIdentifier;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.persistence.entity.ResourceJpaEntity;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Translates between the {@link Resource} domain entity and its JPA row, including the
 * comma-separated encoding described on {@link ResourceJpaEntity}'s Javadoc for {@code scopes}.
 */
public final class ResourceEntityMapper {

    private static final String SEPARATOR = ",";

    private ResourceEntityMapper() {}

    public static ResourceJpaEntity toEntity(Resource resource) {
        return new ResourceJpaEntity(
                resource.id().value(),
                resource.tenantId().value(),
                resource.identifier().value(),
                resource.name(),
                String.join(SEPARATOR, resource.scopes()),
                resource.status(),
                resource.createdAt());
    }

    public static Resource toDomain(ResourceJpaEntity entity) {
        Set<String> scopes = Arrays.stream(entity.getScopes().split(SEPARATOR))
                .map(String::trim)
                .collect(Collectors.toUnmodifiableSet());

        return Resource.reconstitute(
                ResourceId.of(entity.getId()),
                TenantId.of(entity.getTenantId()),
                ResourceIdentifier.of(entity.getIdentifier()),
                entity.getName(),
                scopes,
                entity.getStatus(),
                entity.getCreatedAt());
    }
}
