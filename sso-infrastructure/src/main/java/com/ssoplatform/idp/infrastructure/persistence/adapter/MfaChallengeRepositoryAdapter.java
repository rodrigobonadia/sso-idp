package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.MfaChallengeJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.MfaChallengeEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.MfaChallengeJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link MfaChallengeRepository} output port on top of Spring Data JPA. */
@Repository
public class MfaChallengeRepositoryAdapter implements MfaChallengeRepository {

    private final MfaChallengeJpaRepository jpaRepository;

    public MfaChallengeRepositoryAdapter(MfaChallengeJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public MfaChallenge save(MfaChallenge challenge) {
        MfaChallengeJpaEntity saved = jpaRepository.save(MfaChallengeEntityMapper.toEntity(challenge));
        return MfaChallengeEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<MfaChallenge> findByTokenHash(TokenHash tokenHash) {
        return jpaRepository.findByTokenHash(tokenHash.value()).map(MfaChallengeEntityMapper::toDomain);
    }
}
