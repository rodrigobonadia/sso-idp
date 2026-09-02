package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.ResourceRepository;
import com.ssoplatform.idp.domain.resource.Resource;
import com.ssoplatform.idp.domain.resource.ResourceIdentifier;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.persistence.entity.ResourceJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.ResourceEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.ResourceJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link ResourceRepository} output port on top of Spring Data JPA. */
@Repository
public class ResourceRepositoryAdapter implements ResourceRepository {

    private final ResourceJpaRepository jpaRepository;

    public ResourceRepositoryAdapter(ResourceJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Resource save(Resource resource) {
        ResourceJpaEntity saved = jpaRepository.save(ResourceEntityMapper.toEntity(resource));
        return ResourceEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<Resource> findByTenantIdAndIdentifier(TenantId tenantId, ResourceIdentifier identifier) {
        return jpaRepository
                .findByTenantIdAndIdentifier(tenantId.value(), identifier.value())
                .map(ResourceEntityMapper::toDomain);
    }
}
