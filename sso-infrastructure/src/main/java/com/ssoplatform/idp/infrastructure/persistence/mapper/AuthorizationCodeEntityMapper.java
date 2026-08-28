package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.authorization.AuthorizationCodeId;
import com.ssoplatform.idp.domain.authorization.CodeChallenge;
import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.AuthorizationCodeJpaEntity;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Translates between the {@link AuthorizationCode} domain entity and its JPA row. */
public final class AuthorizationCodeEntityMapper {

    private AuthorizationCodeEntityMapper() {}

    public static AuthorizationCodeJpaEntity toEntity(AuthorizationCode code) {
        return new AuthorizationCodeJpaEntity(
                code.id().value(),
                code.tenantId().value(),
                code.oauthClientId().value(),
                code.userId().value(),
                code.codeHash().value(),
                code.redirectUri().value(),
                String.join(",", code.scopes()),
                code.codeChallenge().value(),
                code.expiresAt(),
                code.consumedAt(),
                code.createdAt());
    }

    public static AuthorizationCode toDomain(AuthorizationCodeJpaEntity entity) {
        return AuthorizationCode.reconstitute(
                AuthorizationCodeId.of(entity.getId()),
                TenantId.of(entity.getTenantId()),
                OAuthClientId.of(entity.getOauthClientId()),
                UserId.of(entity.getUserId()),
                TokenHash.of(entity.getCodeHash()),
                RedirectUri.of(entity.getRedirectUri()),
                parseScopes(entity.getScopes()),
                CodeChallenge.of(entity.getCodeChallenge()),
                entity.getExpiresAt(),
                entity.getConsumedAt(),
                entity.getCreatedAt());
    }

    private static Set<String> parseScopes(String commaSeparated) {
        return Arrays.stream(commaSeparated.split(","))
                .map(String::trim)
                .filter(scope -> !scope.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
