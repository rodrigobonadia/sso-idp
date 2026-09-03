package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredentialId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.EmailOtpCredentialJpaEntity;

/** Translates between the {@link EmailOtpCredential} domain entity and its JPA row. */
public final class EmailOtpCredentialEntityMapper {

    private EmailOtpCredentialEntityMapper() {}

    public static EmailOtpCredentialJpaEntity toEntity(EmailOtpCredential credential) {
        return new EmailOtpCredentialJpaEntity(
                credential.id().value(),
                credential.userId().value(),
                credential.status(),
                credential.createdAt(),
                credential.activatedAt());
    }

    public static EmailOtpCredential toDomain(EmailOtpCredentialJpaEntity entity) {
        return EmailOtpCredential.reconstitute(
                EmailOtpCredentialId.of(entity.getId()),
                UserId.of(entity.getUserId()),
                entity.getStatus(),
                entity.getCreatedAt(),
                entity.getActivatedAt());
    }
}
