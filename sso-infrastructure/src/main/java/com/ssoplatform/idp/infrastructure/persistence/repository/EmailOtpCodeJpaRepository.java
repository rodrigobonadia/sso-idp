package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.infrastructure.persistence.entity.EmailOtpCodeJpaEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface EmailOtpCodeJpaRepository extends JpaRepository<EmailOtpCodeJpaEntity, UUID> {

    Optional<EmailOtpCodeJpaEntity> findByMfaChallengeId(UUID mfaChallengeId);

    /** {@code First}/{@code OrderByCreatedAtDesc} limits this to the single most recently issued
     * row for the user/purpose - see {@code EmailOtpCodeRepositoryAdapter}. */
    Optional<EmailOtpCodeJpaEntity> findFirstByUserIdAndPurposeOrderByCreatedAtDesc(
            UUID userId, EmailOtpPurpose purpose);

    void deleteByUserIdAndPurpose(UUID userId, EmailOtpPurpose purpose);
}
