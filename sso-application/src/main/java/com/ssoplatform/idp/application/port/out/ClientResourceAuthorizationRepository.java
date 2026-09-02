package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.resource.ClientResourceAuthorization;
import com.ssoplatform.idp.domain.resource.ResourceId;
import java.util.Optional;

/**
 * Output port for {@link ClientResourceAuthorization} persistence.
 *
 * <p>Looked up by the {@code (oauthClientId, resourceId)} pair, mirroring the unique constraint on
 * {@code client_resource_authorizations}: a client either has exactly one authorization for a
 * given resource (carrying its granted-scopes subset) or none at all.
 *
 * <p>{@code save} is not yet called by any use case in this sub-phase - authorizations are
 * provisioned directly via SQL for now, exactly like {@code OAuthClient} and {@code Resource}
 * themselves (see {@code architecture_decisions.md}).
 */
public interface ClientResourceAuthorizationRepository {

    ClientResourceAuthorization save(ClientResourceAuthorization authorization);

    Optional<ClientResourceAuthorization> findByOAuthClientIdAndResourceId(
            OAuthClientId oauthClientId, ResourceId resourceId);
}
