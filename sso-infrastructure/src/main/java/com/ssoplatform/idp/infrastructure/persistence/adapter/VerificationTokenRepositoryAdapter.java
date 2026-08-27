package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.VerificationTokenRepository;
import com.ssoplatform.idp.domain.verification.EmailVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.EmailVerificationTokenJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.EmailVerificationTokenEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.EmailVerificationTokenJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link VerificationTokenRepository} output port on top of Spring Data JPA. */
@Repository
public class VerificationTokenRepositoryAdapter implements VerificationTokenRepository {

    private final EmailVerificationTokenJpaRepository jpaRepository;

    public VerificationTokenRepositoryAdapter(EmailVerificationTokenJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public EmailVerificationToken save(EmailVerificationToken token) {
        EmailVerificationTokenJpaEntity saved =
                jpaRepository.save(EmailVerificationTokenEntityMapper.toEntity(token));
        return EmailVerificationTokenEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<EmailVerificationToken> findByTokenHash(TokenHash tokenHash) {
        return jpaRepository
                .findByTokenHash(tokenHash.value())
                .map(EmailVerificationTokenEntityMapper::toDomain);
    }
}
