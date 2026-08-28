package com.ssoplatform.idp.application.usecase.signingkey;

import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.util.List;
import java.util.Objects;

/**
 * Lists every signing key for a tenant - current and retired alike - as needed to build that
 * tenant's JWKS document. The tenant is assumed already resolved and active by the caller (the web
 * layer's {@code TenantContext}, populated from the request's subdomain), exactly like {@code
 * LoginUseCase} and friends - this use case does not re-validate tenant existence itself.
 */
public class ListSigningKeysUseCase {

    private final SigningKeyRepository signingKeyRepository;

    public ListSigningKeysUseCase(SigningKeyRepository signingKeyRepository) {
        this.signingKeyRepository =
                Objects.requireNonNull(signingKeyRepository, "signingKeyRepository must not be null");
    }

    public List<SigningKeySummary> execute(ListSigningKeysQuery query) {
        Objects.requireNonNull(query, "query must not be null");
        TenantId tenantId = TenantId.of(query.tenantId());

        List<SigningKey> keys = signingKeyRepository.findAllByTenantId(tenantId);
        return keys.stream()
                .map(key -> new SigningKeySummary(key.kid().value(), key.algorithm(), key.publicKey().value()))
                .toList();
    }
}
