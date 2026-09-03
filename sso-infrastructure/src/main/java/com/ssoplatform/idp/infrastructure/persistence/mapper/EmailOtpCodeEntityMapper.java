package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeId;
import com.ssoplatform.idp.domain.mfa.MfaChallengeId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.EmailOtpCodeJpaEntity;

/** Translates between the {@link EmailOtpCode} domain entity and its JPA row. */
public final class EmailOtpCodeEntityMapper {

    private EmailOtpCodeEntityMapper() {}

    public static EmailOtpCodeJpaEntity toEntity(EmailOtpCode code) {
        return new EmailOtpCodeJpaEntity(
                code.id().value(),
                code.userId().value(),
                code.purpose(),
                code.mfaChallengeId().map(MfaChallengeId::value).orElse(null),
                code.codeHash().value(),
                code.expiresAt(),
                code.consumedAt(),
                code.failedAttempts(),
                code.createdAt());
    }

    public static EmailOtpCode toDomain(EmailOtpCodeJpaEntity entity) {
        return EmailOtpCode.reconstitute(
                EmailOtpCodeId.of(entity.getId()),
                UserId.of(entity.getUserId()),
                entity.getPurpose(),
                entity.getMfaChallengeId() == null ? null : MfaChallengeId.of(entity.getMfaChallengeId()),
                EmailOtpCodeHash.of(entity.getCodeHash()),
                entity.getExpiresAt(),
                entity.getConsumedAt(),
                entity.getFailedAttempts(),
                entity.getCreatedAt());
    }
}
