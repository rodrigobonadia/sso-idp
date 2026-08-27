package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
import com.ssoplatform.idp.domain.passwordreset.PasswordResetTokenId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.PasswordResetTokenJpaEntity;

/** Translates between the {@link PasswordResetToken} domain entity and its JPA row. */
public final class PasswordResetTokenEntityMapper {

    private PasswordResetTokenEntityMapper() {}

    public static PasswordResetTokenJpaEntity toEntity(PasswordResetToken token) {
        return new PasswordResetTokenJpaEntity(
                token.id().value(),
                token.userId().value(),
                token.tokenHash().value(),
                token.expiresAt(),
                token.consumedAt(),
                token.createdAt());
    }

    public static PasswordResetToken toDomain(PasswordResetTokenJpaEntity entity) {
        return PasswordResetToken.reconstitute(
                PasswordResetTokenId.of(entity.getId()),
                UserId.of(entity.getUserId()),
                TokenHash.of(entity.getTokenHash()),
                entity.getExpiresAt(),
                entity.getConsumedAt(),
                entity.getCreatedAt());
    }
}
