package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.PasswordResetTokenRepository;
import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.PasswordResetTokenJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.PasswordResetTokenEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.PasswordResetTokenJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link PasswordResetTokenRepository} output port on top of Spring Data JPA. */
@Repository
public class PasswordResetTokenRepositoryAdapter implements PasswordResetTokenRepository {

    private final PasswordResetTokenJpaRepository jpaRepository;

    public PasswordResetTokenRepositoryAdapter(PasswordResetTokenJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public PasswordResetToken save(PasswordResetToken token) {
        PasswordResetTokenJpaEntity saved =
                jpaRepository.save(PasswordResetTokenEntityMapper.toEntity(token));
        return PasswordResetTokenEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<PasswordResetToken> findByTokenHash(TokenHash tokenHash) {
        return jpaRepository
                .findByTokenHash(tokenHash.value())
                .map(PasswordResetTokenEntityMapper::toDomain);
    }
}
