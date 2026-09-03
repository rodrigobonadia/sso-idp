package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.EmailOtpCredentialJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.EmailOtpCredentialEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.EmailOtpCredentialJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** Adapter implementing the {@link EmailOtpCredentialRepository} output port on top of Spring Data
 * JPA. Mirrors {@code TotpCredentialRepositoryAdapter} exactly. */
@Repository
public class EmailOtpCredentialRepositoryAdapter implements EmailOtpCredentialRepository {

    private final EmailOtpCredentialJpaRepository jpaRepository;

    public EmailOtpCredentialRepositoryAdapter(EmailOtpCredentialJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public EmailOtpCredential save(EmailOtpCredential credential) {
        EmailOtpCredentialJpaEntity saved = jpaRepository.save(EmailOtpCredentialEntityMapper.toEntity(credential));
        return EmailOtpCredentialEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<EmailOtpCredential> findByUserId(UserId userId) {
        return jpaRepository.findByUserId(userId.value()).map(EmailOtpCredentialEntityMapper::toDomain);
    }

    /**
     * A hard-delete derived query (unlike {@code save}, which is self-transactional via
     * {@code SimpleJpaRepository}'s inherited default) needs its own explicit transaction
     * boundary - see {@code TotpCredentialRepositoryAdapter#deleteByUserId}'s Javadoc for the
     * real Phase 4.1 bug this lesson comes from; applied here proactively from day one.
     */
    @Override
    @Transactional
    public void deleteByUserId(UserId userId) {
        jpaRepository.deleteByUserId(userId.value());
    }
}
