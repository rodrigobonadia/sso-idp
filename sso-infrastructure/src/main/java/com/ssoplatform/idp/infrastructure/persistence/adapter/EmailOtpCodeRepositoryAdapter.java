package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.domain.mfa.MfaChallengeId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.EmailOtpCodeJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.EmailOtpCodeEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.EmailOtpCodeJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/** Adapter implementing the {@link EmailOtpCodeRepository} output port on top of Spring Data JPA. */
@Repository
public class EmailOtpCodeRepositoryAdapter implements EmailOtpCodeRepository {

    private final EmailOtpCodeJpaRepository jpaRepository;

    public EmailOtpCodeRepositoryAdapter(EmailOtpCodeJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public EmailOtpCode save(EmailOtpCode code) {
        EmailOtpCodeJpaEntity saved = jpaRepository.save(EmailOtpCodeEntityMapper.toEntity(code));
        return EmailOtpCodeEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<EmailOtpCode> findByMfaChallengeId(MfaChallengeId mfaChallengeId) {
        return jpaRepository.findByMfaChallengeId(mfaChallengeId.value()).map(EmailOtpCodeEntityMapper::toDomain);
    }

    @Override
    public Optional<EmailOtpCode> findLatestByUserIdAndPurpose(UserId userId, EmailOtpPurpose purpose) {
        return jpaRepository
                .findFirstByUserIdAndPurposeOrderByCreatedAtDesc(userId.value(), purpose)
                .map(EmailOtpCodeEntityMapper::toDomain);
    }

    /**
     * A hard-delete derived query - MUST carry an explicit transaction boundary, exactly like
     * {@code TotpCredentialRepositoryAdapter#deleteByUserId}'s Javadoc explains (the real Phase
     * 4.1 bug); applied here proactively from day one rather than waiting to rediscover it.
     */
    @Override
    @Transactional
    public void deleteByUserIdAndPurpose(UserId userId, EmailOtpPurpose purpose) {
        jpaRepository.deleteByUserIdAndPurpose(userId.value(), purpose);
    }
}
