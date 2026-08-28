package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.infrastructure.persistence.entity.OAuthClientJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.OAuthClientEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.OAuthClientJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link OAuthClientRepository} output port on top of Spring Data JPA. */
@Repository
public class OAuthClientRepositoryAdapter implements OAuthClientRepository {

    private final OAuthClientJpaRepository jpaRepository;

    public OAuthClientRepositoryAdapter(OAuthClientJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public OAuthClient save(OAuthClient client) {
        OAuthClientJpaEntity saved = jpaRepository.save(OAuthClientEntityMapper.toEntity(client));
        return OAuthClientEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<OAuthClient> findByClientId(ClientId clientId) {
        return jpaRepository.findByClientId(clientId.value()).map(OAuthClientEntityMapper::toDomain);
    }
}
