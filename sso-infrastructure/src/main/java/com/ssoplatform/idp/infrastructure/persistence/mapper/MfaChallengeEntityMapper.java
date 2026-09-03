package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.MfaChallengeId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.MfaChallengeJpaEntity;

/** Translates between the {@link MfaChallenge} domain entity and its JPA row. */
public final class MfaChallengeEntityMapper {

    private MfaChallengeEntityMapper() {}

    public static MfaChallengeJpaEntity toEntity(MfaChallenge challenge) {
        return new MfaChallengeJpaEntity(
                challenge.id().value(),
                challenge.userId().value(),
                challenge.tenantId().value(),
                challenge.tokenHash().value(),
                challenge.expiresAt(),
                challenge.consumedAt(),
                challenge.createdAt());
    }

    public static MfaChallenge toDomain(MfaChallengeJpaEntity entity) {
        return MfaChallenge.reconstitute(
                MfaChallengeId.of(entity.getId()),
                UserId.of(entity.getUserId()),
                TenantId.of(entity.getTenantId()),
                TokenHash.of(entity.getTokenHash()),
                entity.getExpiresAt(),
                entity.getConsumedAt(),
                entity.getCreatedAt());
    }
}
