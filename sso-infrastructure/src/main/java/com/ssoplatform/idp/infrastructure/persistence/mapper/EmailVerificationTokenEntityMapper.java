package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.EmailVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenId;
import com.ssoplatform.idp.infrastructure.persistence.entity.EmailVerificationTokenJpaEntity;

/** Translates between the {@link EmailVerificationToken} domain entity and its JPA row. */
public final class EmailVerificationTokenEntityMapper {

    private EmailVerificationTokenEntityMapper() {}

    public static EmailVerificationTokenJpaEntity toEntity(EmailVerificationToken token) {
        return new EmailVerificationTokenJpaEntity(
                token.id().value(),
                token.userId().value(),
                token.tokenHash().value(),
                token.expiresAt(),
                token.consumedAt(),
                token.createdAt());
    }

    public static EmailVerificationToken toDomain(EmailVerificationTokenJpaEntity entity) {
        return EmailVerificationToken.reconstitute(
                VerificationTokenId.of(entity.getId()),
                UserId.of(entity.getUserId()),
                TokenHash.of(entity.getTokenHash()),
                entity.getExpiresAt(),
                entity.getConsumedAt(),
                entity.getCreatedAt());
    }
}
