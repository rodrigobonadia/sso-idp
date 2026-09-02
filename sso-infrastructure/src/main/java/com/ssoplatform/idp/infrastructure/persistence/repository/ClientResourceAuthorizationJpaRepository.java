package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.infrastructure.persistence.entity.ClientResourceAuthorizationJpaEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface ClientResourceAuthorizationJpaRepository
        extends JpaRepository<ClientResourceAuthorizationJpaEntity, UUID> {

    Optional<ClientResourceAuthorizationJpaEntity> findByOauthClientIdAndResourceId(UUID oauthClientId, UUID resourceId);
}
