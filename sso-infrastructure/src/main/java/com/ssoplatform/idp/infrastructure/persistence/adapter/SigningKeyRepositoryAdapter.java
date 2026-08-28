package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.signingkey.SigningKeyStatus;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.persistence.entity.SigningKeyJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.SigningKeyEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.SigningKeyJpaRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link SigningKeyRepository} output port on top of Spring Data JPA. */
@Repository
public class SigningKeyRepositoryAdapter implements SigningKeyRepository {

    private final SigningKeyJpaRepository jpaRepository;

    public SigningKeyRepositoryAdapter(SigningKeyJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public SigningKey save(SigningKey key) {
        SigningKeyJpaEntity saved = jpaRepository.save(SigningKeyEntityMapper.toEntity(key));
        return SigningKeyEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<SigningKey> findCurrentByTenantId(TenantId tenantId) {
        return jpaRepository
                .findByTenantIdAndStatus(tenantId.value(), SigningKeyStatus.CURRENT)
                .map(SigningKeyEntityMapper::toDomain);
    }

    @Override
    public List<SigningKey> findAllByTenantId(TenantId tenantId) {
        return jpaRepository.findByTenantId(tenantId.value()).stream()
                .map(SigningKeyEntityMapper::toDomain)
                .toList();
    }
}
