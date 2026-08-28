package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.domain.signingkey.SigningKeyStatus;
import com.ssoplatform.idp.infrastructure.persistence.entity.SigningKeyJpaEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface SigningKeyJpaRepository extends JpaRepository<SigningKeyJpaEntity, UUID> {

    Optional<SigningKeyJpaEntity> findByTenantIdAndStatus(UUID tenantId, SigningKeyStatus status);

    List<SigningKeyJpaEntity> findByTenantId(UUID tenantId);
}
