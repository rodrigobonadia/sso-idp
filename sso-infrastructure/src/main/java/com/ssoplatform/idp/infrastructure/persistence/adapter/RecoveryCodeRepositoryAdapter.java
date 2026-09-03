package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.RecoveryCodeJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.RecoveryCodeEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.RecoveryCodeJpaRepository;
import java.util.List;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** Adapter implementing the {@link RecoveryCodeRepository} output port on top of Spring Data JPA. */
@Repository
public class RecoveryCodeRepositoryAdapter implements RecoveryCodeRepository {

    private final RecoveryCodeJpaRepository jpaRepository;

    public RecoveryCodeRepositoryAdapter(RecoveryCodeJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public List<RecoveryCode> saveAll(List<RecoveryCode> codes) {
        List<RecoveryCodeJpaEntity> entities = codes.stream().map(RecoveryCodeEntityMapper::toEntity).toList();
        return jpaRepository.saveAll(entities).stream().map(RecoveryCodeEntityMapper::toDomain).toList();
    }

    @Override
    public RecoveryCode save(RecoveryCode code) {
        RecoveryCodeJpaEntity saved = jpaRepository.save(RecoveryCodeEntityMapper.toEntity(code));
        return RecoveryCodeEntityMapper.toDomain(saved);
    }

    @Override
    public List<RecoveryCode> findUnconsumedByUserId(UserId userId) {
        return jpaRepository.findByUserIdAndConsumedAtIsNull(userId.value()).stream()
                .map(RecoveryCodeEntityMapper::toDomain)
                .toList();
    }

    /** See {@link TotpCredentialRepositoryAdapter#deleteByUserId} - same derived-delete-query
     * transaction requirement. */
    @Override
    @Transactional
    public void deleteAllByUserId(UserId userId) {
        jpaRepository.deleteByUserId(userId.value());
    }
}
