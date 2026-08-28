package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.infrastructure.persistence.entity.AuthorizationCodeJpaEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface AuthorizationCodeJpaRepository extends JpaRepository<AuthorizationCodeJpaEntity, UUID> {

    Optional<AuthorizationCodeJpaEntity> findByCodeHash(String codeHash);
}
