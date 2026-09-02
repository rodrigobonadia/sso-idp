package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.resource.ClientResourceAuthorization;
import com.ssoplatform.idp.domain.resource.ClientResourceAuthorizationId;
import com.ssoplatform.idp.domain.resource.ResourceId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.persistence.entity.ClientResourceAuthorizationJpaEntity;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Translates between the {@link ClientResourceAuthorization} domain entity and its JPA row,
 * including the comma-separated encoding described on {@link
 * ClientResourceAuthorizationJpaEntity}'s Javadoc for {@code grantedScopes}.
 */
public final class ClientResourceAuthorizationEntityMapper {

    private static final String SEPARATOR = ",";

    private ClientResourceAuthorizationEntityMapper() {}

    public static ClientResourceAuthorizationJpaEntity toEntity(ClientResourceAuthorization authorization) {
        return new ClientResourceAuthorizationJpaEntity(
                authorization.id().value(),
                authorization.tenantId().value(),
                authorization.oauthClientId().value(),
                authorization.resourceId().value(),
                String.join(SEPARATOR, authorization.grantedScopes()),
                authorization.createdAt());
    }

    public static ClientResourceAuthorization toDomain(ClientResourceAuthorizationJpaEntity entity) {
        Set<String> grantedScopes = Arrays.stream(entity.getGrantedScopes().split(SEPARATOR))
                .map(String::trim)
                .collect(Collectors.toUnmodifiableSet());

        return ClientResourceAuthorization.reconstitute(
                ClientResourceAuthorizationId.of(entity.getId()),
                TenantId.of(entity.getTenantId()),
                OAuthClientId.of(entity.getOauthClientId()),
                ResourceId.of(entity.getResourceId()),
                grantedScopes,
                entity.getCreatedAt());
    }
}
