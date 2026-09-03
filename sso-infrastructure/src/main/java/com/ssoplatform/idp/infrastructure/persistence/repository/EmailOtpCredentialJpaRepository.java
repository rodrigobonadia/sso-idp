package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.infrastructure.persistence.entity.EmailOtpCredentialJpaEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface EmailOtpCredentialJpaRepository extends JpaRepository<EmailOtpCredentialJpaEntity, UUID> {

    Optional<EmailOtpCredentialJpaEntity> findByUserId(UUID userId);

    void deleteByUserId(UUID userId);
}
