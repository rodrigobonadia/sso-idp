package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.AuthorizationCodeRepository;
import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.AuthorizationCodeJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.AuthorizationCodeEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.AuthorizationCodeJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link AuthorizationCodeRepository} output port on top of Spring Data JPA. */
@Repository
public class AuthorizationCodeRepositoryAdapter implements AuthorizationCodeRepository {

    private final AuthorizationCodeJpaRepository jpaRepository;

    public AuthorizationCodeRepositoryAdapter(AuthorizationCodeJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public AuthorizationCode save(AuthorizationCode authorizationCode) {
        AuthorizationCodeJpaEntity saved =
                jpaRepository.save(AuthorizationCodeEntityMapper.toEntity(authorizationCode));
        return AuthorizationCodeEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<AuthorizationCode> findByCodeHash(TokenHash codeHash) {
        return jpaRepository.findByCodeHash(codeHash.value()).map(AuthorizationCodeEntityMapper::toDomain);
    }
}
