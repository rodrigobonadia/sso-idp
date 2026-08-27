package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.UserJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.UserEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.UserJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/**
 * Adapter implementing the {@link UserRepository} output port on top of Spring Data JPA.
 * Every query is scoped by {@code tenantId}, keeping the multi-tenancy boundary explicit
 * at the one place where the application layer talks to persistence.
 */
@Repository
public class UserRepositoryAdapter implements UserRepository {

    private final UserJpaRepository jpaRepository;

    public UserRepositoryAdapter(UserJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public User save(User user) {
        UserJpaEntity saved = jpaRepository.save(UserEntityMapper.toEntity(user));
        return UserEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<User> findById(UserId id) {
        return jpaRepository.findById(id.value()).map(UserEntityMapper::toDomain);
    }

    @Override
    public Optional<User> findByTenantIdAndEmail(TenantId tenantId, Email email) {
        return jpaRepository
                .findByTenantIdAndEmail(tenantId.value(), email.value())
                .map(UserEntityMapper::toDomain);
    }

    @Override
    public boolean existsByTenantIdAndEmail(TenantId tenantId, Email email) {
        return jpaRepository.existsByTenantIdAndEmail(tenantId.value(), email.value());
    }
}
