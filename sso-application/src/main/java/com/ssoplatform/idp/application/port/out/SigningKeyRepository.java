package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.util.List;
import java.util.Optional;

/**
 * Output port for {@link SigningKey} persistence, always scoped by {@link TenantId} - unlike
 * {@link OAuthClientRepository} (looked up by a globally-unique {@code client_id}), a signing key
 * has no public-facing identifier that is unique on its own across tenants, so every lookup here
 * takes the tenant explicitly.
 *
 * <p>{@link #findAllByTenantId} deliberately returns every key regardless of status - both the
 * {@code CURRENT} one and any {@code RETIRED} ones - since the JWKS endpoint must keep publishing
 * a retired key's public half for as long as tokens signed under it might still need verifying.
 */
public interface SigningKeyRepository {

    SigningKey save(SigningKey key);

    Optional<SigningKey> findCurrentByTenantId(TenantId tenantId);

    List<SigningKey> findAllByTenantId(TenantId tenantId);
}
