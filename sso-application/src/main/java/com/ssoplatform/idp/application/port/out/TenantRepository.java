package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import java.util.Optional;

/**
 * Output port for {@link Tenant} persistence. Implemented by an adapter in
 * {@code sso-infrastructure} (JPA/Postgres) - the application layer only knows this interface,
 * never the persistence technology behind it (Dependency Inversion Principle).
 */
public interface TenantRepository {

    Tenant save(Tenant tenant);

    Optional<Tenant> findById(TenantId id);

    Optional<Tenant> findBySlug(TenantSlug slug);

    boolean existsBySlug(TenantSlug slug);
}
