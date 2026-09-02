package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.persistence.entity.OAuthClientJpaEntity;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Translates between the {@link OAuthClient} domain entity and its JPA row, including the
 * comma-separated encoding described on {@link OAuthClientJpaEntity}'s Javadoc for its three
 * multi-valued columns.
 */
public final class OAuthClientEntityMapper {

    private static final String SEPARATOR = ",";

    private OAuthClientEntityMapper() {}

    public static OAuthClientJpaEntity toEntity(OAuthClient client) {
        return new OAuthClientJpaEntity(
                client.id().value(),
                client.tenantId().value(),
                client.clientId().value(),
                client.clientSecretHash() == null ? null : client.clientSecretHash().value(),
                client.name(),
                join(client.redirectUris().stream().map(RedirectUri::value)),
                join(client.allowedScopes().stream()),
                join(client.allowedGrantTypes().stream().map(Enum::name)),
                client.status(),
                client.createdAt());
    }

    public static OAuthClient toDomain(OAuthClientJpaEntity entity) {
        Set<RedirectUri> redirectUris =
                split(entity.getRedirectUris()).map(RedirectUri::of).collect(Collectors.toUnmodifiableSet());
        Set<String> allowedScopes = split(entity.getAllowedScopes()).collect(Collectors.toUnmodifiableSet());
        Set<GrantType> allowedGrantTypes =
                split(entity.getAllowedGrantTypes()).map(GrantType::valueOf).collect(Collectors.toUnmodifiableSet());

        return OAuthClient.reconstitute(
                OAuthClientId.of(entity.getId()),
                TenantId.of(entity.getTenantId()),
                ClientId.of(entity.getClientId()),
                entity.getClientSecretHash() == null ? null : ClientSecretHash.of(entity.getClientSecretHash()),
                entity.getName(),
                redirectUris,
                allowedScopes,
                allowedGrantTypes,
                entity.getStatus(),
                entity.getCreatedAt());
    }

    private static String join(java.util.stream.Stream<String> values) {
        return values.collect(Collectors.joining(SEPARATOR));
    }

    /**
     * {@code String.split} on an empty string yields a single blank element rather than an empty
     * array, which would otherwise make an empty {@code redirect_uris} column (valid for a client
     * not authorized for {@code AUTHORIZATION_CODE} - see {@link OAuthClient}'s Javadoc) fail to
     * reload via {@link RedirectUri#of}. Guarding for blank here keeps this shared helper correct
     * for every one of this entity's three multi-valued columns, even though only {@code
     * redirect_uris} can actually be empty today.
     */
    private static java.util.stream.Stream<String> split(String commaSeparated) {
        if (commaSeparated == null || commaSeparated.isBlank()) {
            return java.util.stream.Stream.empty();
        }
        return java.util.Arrays.stream(commaSeparated.split(SEPARATOR)).map(String::trim);
    }
}
