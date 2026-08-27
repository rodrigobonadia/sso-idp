package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Optional;

/**
 * Output port for {@link User} persistence, always scoped by tenant so that the
 * multi-tenancy isolation invariant is visible right at the boundary of the application layer.
 */
public interface UserRepository {

    User save(User user);

    Optional<User> findById(UserId id);

    Optional<User> findByTenantIdAndEmail(TenantId tenantId, Email email);

    boolean existsByTenantIdAndEmail(TenantId tenantId, Email email);
}
