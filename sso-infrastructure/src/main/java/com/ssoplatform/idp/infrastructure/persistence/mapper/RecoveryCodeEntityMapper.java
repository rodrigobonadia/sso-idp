package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.RecoveryCodeJpaEntity;

/** Translates between the {@link RecoveryCode} domain entity and its JPA row. */
public final class RecoveryCodeEntityMapper {

    private RecoveryCodeEntityMapper() {}

    public static RecoveryCodeJpaEntity toEntity(RecoveryCode code) {
        return new RecoveryCodeJpaEntity(
                code.id().value(), code.userId().value(), code.codeHash().value(), code.consumedAt(), code.createdAt());
    }

    public static RecoveryCode toDomain(RecoveryCodeJpaEntity entity) {
        return RecoveryCode.reconstitute(
                RecoveryCodeId.of(entity.getId()),
                UserId.of(entity.getUserId()),
                RecoveryCodeHash.of(entity.getCodeHash()),
                entity.getConsumedAt(),
                entity.getCreatedAt());
    }
}
