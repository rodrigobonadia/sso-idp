package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.ClientResourceAuthorizationRepository;
import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.resource.ClientResourceAuthorization;
import com.ssoplatform.idp.domain.resource.ResourceId;
import com.ssoplatform.idp.infrastructure.persistence.entity.ClientResourceAuthorizationJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.ClientResourceAuthorizationEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.ClientResourceAuthorizationJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link ClientResourceAuthorizationRepository} output port on top of Spring Data JPA. */
@Repository
public class ClientResourceAuthorizationRepositoryAdapter implements ClientResourceAuthorizationRepository {

    private final ClientResourceAuthorizationJpaRepository jpaRepository;

    public ClientResourceAuthorizationRepositoryAdapter(ClientResourceAuthorizationJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public ClientResourceAuthorization save(ClientResourceAuthorization authorization) {
        ClientResourceAuthorizationJpaEntity saved =
                jpaRepository.save(ClientResourceAuthorizationEntityMapper.toEntity(authorization));
        return ClientResourceAuthorizationEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<ClientResourceAuthorization> findByOAuthClientIdAndResourceId(
            OAuthClientId oauthClientId, ResourceId resourceId) {
        return jpaRepository
                .findByOauthClientIdAndResourceId(oauthClientId.value(), resourceId.value())
                .map(ClientResourceAuthorizationEntityMapper::toDomain);
    }
}
