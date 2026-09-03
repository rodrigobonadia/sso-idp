package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.TotpCredentialJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.TotpCredentialEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.TotpCredentialJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** Adapter implementing the {@link TotpCredentialRepository} output port on top of Spring Data JPA. */
@Repository
public class TotpCredentialRepositoryAdapter implements TotpCredentialRepository {

    private final TotpCredentialJpaRepository jpaRepository;

    public TotpCredentialRepositoryAdapter(TotpCredentialJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public TotpCredential save(TotpCredential credential) {
        TotpCredentialJpaEntity saved = jpaRepository.save(TotpCredentialEntityMapper.toEntity(credential));
        return TotpCredentialEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<TotpCredential> findByUserId(UserId userId) {
        return jpaRepository.findByUserId(userId.value()).map(TotpCredentialEntityMapper::toDomain);
    }

    /**
     * A hard-delete derived query (unlike {@code save}, which is self-transactional via
     * {@code SimpleJpaRepository}'s inherited default) needs its own explicit transaction
     * boundary - discovered by a real end-to-end test run, not by inspection: without this,
     * Hibernate throws {@code TransactionRequiredException} the moment the derived delete
     * query actually matches a row to remove.
     */
    @Override
    @Transactional
    public void deleteByUserId(UserId userId) {
        jpaRepository.deleteByUserId(userId.value());
    }
}
