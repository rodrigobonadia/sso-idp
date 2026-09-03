package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.infrastructure.persistence.entity.RecoveryCodeJpaEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface RecoveryCodeJpaRepository extends JpaRepository<RecoveryCodeJpaEntity, UUID> {

    List<RecoveryCodeJpaEntity> findByUserIdAndConsumedAtIsNull(UUID userId);

    void deleteByUserId(UUID userId);
}
