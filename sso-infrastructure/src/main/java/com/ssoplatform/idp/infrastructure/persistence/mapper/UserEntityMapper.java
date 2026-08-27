package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.UserJpaEntity;

/** Translates between the {@link User} domain entity and its JPA row representation. */
public final class UserEntityMapper {

    private UserEntityMapper() {}

    public static UserJpaEntity toEntity(User user) {
        return new UserJpaEntity(
                user.id().value(),
                user.tenantId().value(),
                user.email().value(),
                user.passwordHash().value(),
                user.status(),
                user.failedLoginAttempts(),
                user.createdAt());
    }

    public static User toDomain(UserJpaEntity entity) {
        return User.reconstitute(
                UserId.of(entity.getId()),
                TenantId.of(entity.getTenantId()),
                Email.of(entity.getEmail()),
                HashedPassword.of(entity.getPasswordHash()),
                entity.getStatus(),
                entity.getFailedLoginAttempts(),
                entity.getCreatedAt());
    }
}
