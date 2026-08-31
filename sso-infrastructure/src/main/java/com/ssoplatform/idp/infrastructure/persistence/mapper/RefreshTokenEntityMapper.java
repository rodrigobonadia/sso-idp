package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenFamilyId;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenId;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenStatus;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.RefreshTokenJpaEntity;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Translates between the {@link RefreshToken} domain entity and its JPA row. */
public final class RefreshTokenEntityMapper {

    private RefreshTokenEntityMapper() {}

    public static RefreshTokenJpaEntity toEntity(RefreshToken refreshToken) {
        return new RefreshTokenJpaEntity(
                refreshToken.id().value(),
                refreshToken.familyId().value(),
                refreshToken.tenantId().value(),
                refreshToken.oauthClientId().value(),
                refreshToken.userId().value(),
                refreshToken.tokenHash().value(),
                String.join(",", refreshToken.scopes()),
                refreshToken.status().name(),
                refreshToken.familyExpiresAt(),
                refreshToken.createdAt());
    }

    public static RefreshToken toDomain(RefreshTokenJpaEntity entity) {
        return RefreshToken.reconstitute(
                RefreshTokenId.of(entity.getId()),
                RefreshTokenFamilyId.of(entity.getFamilyId()),
                TenantId.of(entity.getTenantId()),
                OAuthClientId.of(entity.getOauthClientId()),
                UserId.of(entity.getUserId()),
                TokenHash.of(entity.getTokenHash()),
                parseScopes(entity.getScopes()),
                RefreshTokenStatus.valueOf(entity.getStatus()),
                entity.getFamilyExpiresAt(),
                entity.getCreatedAt());
    }

    private static Set<String> parseScopes(String commaSeparated) {
        return Arrays.stream(commaSeparated.split(","))
                .map(String::trim)
                .filter(scope -> !scope.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
