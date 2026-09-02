package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.DeviceCodeId;
import com.ssoplatform.idp.domain.devicecode.DeviceCodeStatus;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.DeviceCodeJpaEntity;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Translates between the {@link DeviceCode} domain entity and its JPA row. */
public final class DeviceCodeEntityMapper {

    private DeviceCodeEntityMapper() {}

    public static DeviceCodeJpaEntity toEntity(DeviceCode deviceCode) {
        return new DeviceCodeJpaEntity(
                deviceCode.id().value(),
                deviceCode.tenantId().value(),
                deviceCode.oauthClientId().value(),
                deviceCode.deviceCodeHash().value(),
                deviceCode.userCode().value(),
                String.join(",", deviceCode.scopes()),
                deviceCode.status().name(),
                deviceCode.userId() == null ? null : deviceCode.userId().value(),
                deviceCode.expiresAt(),
                deviceCode.lastPolledAt(),
                deviceCode.redeemedAt(),
                deviceCode.createdAt());
    }

    public static DeviceCode toDomain(DeviceCodeJpaEntity entity) {
        return DeviceCode.reconstitute(
                DeviceCodeId.of(entity.getId()),
                TenantId.of(entity.getTenantId()),
                OAuthClientId.of(entity.getOauthClientId()),
                TokenHash.of(entity.getDeviceCodeHash()),
                UserCode.of(entity.getUserCode()),
                parseScopes(entity.getScopes()),
                DeviceCodeStatus.valueOf(entity.getStatus()),
                entity.getUserId() == null ? null : UserId.of(entity.getUserId()),
                entity.getExpiresAt(),
                entity.getLastPolledAt(),
                entity.getRedeemedAt(),
                entity.getCreatedAt());
    }

    private static Set<String> parseScopes(String commaSeparated) {
        return Arrays.stream(commaSeparated.split(","))
                .map(String::trim)
                .filter(scope -> !scope.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
