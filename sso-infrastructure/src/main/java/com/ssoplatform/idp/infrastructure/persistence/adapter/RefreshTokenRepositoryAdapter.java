package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.RefreshTokenRepository;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenFamilyId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.RefreshTokenJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.RefreshTokenEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.RefreshTokenJpaRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link RefreshTokenRepository} output port on top of Spring Data JPA. */
@Repository
public class RefreshTokenRepositoryAdapter implements RefreshTokenRepository {

    private final RefreshTokenJpaRepository jpaRepository;

    public RefreshTokenRepositoryAdapter(RefreshTokenJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public RefreshToken save(RefreshToken refreshToken) {
        RefreshTokenJpaEntity saved = jpaRepository.save(RefreshTokenEntityMapper.toEntity(refreshToken));
        return RefreshTokenEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<RefreshToken> findByTokenHash(TokenHash tokenHash) {
        return jpaRepository.findByTokenHash(tokenHash.value()).map(RefreshTokenEntityMapper::toDomain);
    }

    @Override
    public List<RefreshToken> findAllByFamilyId(RefreshTokenFamilyId familyId) {
        return jpaRepository.findAllByFamilyId(familyId.value()).stream()
                .map(RefreshTokenEntityMapper::toDomain)
                .toList();
    }
}
