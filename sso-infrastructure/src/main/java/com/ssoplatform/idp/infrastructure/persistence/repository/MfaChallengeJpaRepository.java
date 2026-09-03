package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.infrastructure.persistence.entity.MfaChallengeJpaEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface MfaChallengeJpaRepository extends JpaRepository<MfaChallengeJpaEntity, UUID> {

    Optional<MfaChallengeJpaEntity> findByTokenHash(String tokenHash);
}
