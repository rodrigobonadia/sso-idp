package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.infrastructure.persistence.entity.TenantJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.TenantEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.TenantJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/**
 * Adapter implementing the {@link TenantRepository} output port on top of Spring Data JPA.
 * This is the only class allowed to translate between {@link Tenant} (domain) and
 * {@link TenantJpaEntity} (persistence) - callers in the application layer only ever see
 * the domain type.
 */
@Repository
public class TenantRepositoryAdapter implements TenantRepository {

    private final TenantJpaRepository jpaRepository;

    public TenantRepositoryAdapter(TenantJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Tenant save(Tenant tenant) {
        TenantJpaEntity saved = jpaRepository.save(TenantEntityMapper.toEntity(tenant));
        return TenantEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<Tenant> findById(TenantId id) {
        return jpaRepository.findById(id.value()).map(TenantEntityMapper::toDomain);
    }

    @Override
    public Optional<Tenant> findBySlug(TenantSlug slug) {
        return jpaRepository.findBySlug(slug.value()).map(TenantEntityMapper::toDomain);
    }

    @Override
    public boolean existsBySlug(TenantSlug slug) {
        return jpaRepository.existsBySlug(slug.value());
    }
}
