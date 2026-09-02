package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import java.util.Optional;

/**
 * Output port for {@link OAuthClient} persistence.
 *
 * <p>Looked up by {@link ClientId} alone (not additionally scoped by tenant in the method
 * signature): a {@code client_id} is unique across the whole platform, exactly like {@code
 * TenantSlug} is unique across tenants - a client still belongs to exactly one tenant (see {@link
 * OAuthClient#tenantId()}), but callers such as the {@code /authorize} and {@code /token}
 * endpoints (later Phase 3 sub-phases) are expected to explicitly compare the returned client's
 * {@code tenantId()} against the tenant resolved for the current request, rather than relying on
 * this port to silently filter by tenant - the same defense-in-depth reasoning already documented
 * for {@code RedirectUri}'s exact-match comparison.
 *
 * <p>{@code save} is not yet called by any use case in this sub-phase - clients are provisioned
 * directly via SQL for now (see {@code architecture_decisions.md}) - but is included here to keep
 * this port's shape consistent with every other repository port in the project, ready for Phase
 * 6's admin console to call it directly with no port-level changes needed.
 *
 * <p>{@link #findById} was added in the Device Authorization Grant phase for {@code
 * FindDeviceAuthorizationUseCase}, which only ever has a {@code DeviceCode}'s internal {@link
 * OAuthClientId} in hand (never the public-facing {@link ClientId}) and needs the client's display
 * name for the verification page.
 */
public interface OAuthClientRepository {

    OAuthClient save(OAuthClient client);

    Optional<OAuthClient> findByClientId(ClientId clientId);

    Optional<OAuthClient> findById(OAuthClientId id);
}
