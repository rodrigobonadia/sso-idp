package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.resource.Resource;
import com.ssoplatform.idp.domain.resource.ResourceIdentifier;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.util.Optional;

/**
 * Output port for {@link Resource} persistence.
 *
 * <p>Looked up by {@code (tenantId, identifier)} together, unlike {@link OAuthClientRepository},
 * because a {@link ResourceIdentifier} is only unique WITHIN a tenant (see the unique constraint
 * on {@code resources}), not across the whole platform the way {@code client_id} is - two
 * different tenants are free to register {@code https://api.example.com/orders} as their own,
 * separate resource.
 *
 * <p>{@code save} is not yet called by any use case in this sub-phase - resources are provisioned
 * directly via SQL for now, exactly like {@code OAuthClient} (see {@code
 * architecture_decisions.md}) - but is included here for the same forward-compatibility reason
 * documented on {@link OAuthClientRepository#save}.
 */
public interface ResourceRepository {

    Resource save(Resource resource);

    Optional<Resource> findByTenantIdAndIdentifier(TenantId tenantId, ResourceIdentifier identifier);
}
