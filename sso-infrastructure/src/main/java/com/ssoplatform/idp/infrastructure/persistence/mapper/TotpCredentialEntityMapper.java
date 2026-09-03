package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.mfa.TotpCredentialId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.infrastructure.persistence.entity.TotpCredentialJpaEntity;

/** Translates between the {@link TotpCredential} domain entity and its JPA row. */
public final class TotpCredentialEntityMapper {

    private TotpCredentialEntityMapper() {}

    public static TotpCredentialJpaEntity toEntity(TotpCredential credential) {
        return new TotpCredentialJpaEntity(
                credential.id().value(),
                credential.userId().value(),
                credential.encryptedSecret().value(),
                credential.status(),
                credential.createdAt(),
                credential.activatedAt());
    }

    public static TotpCredential toDomain(TotpCredentialJpaEntity entity) {
        return TotpCredential.reconstitute(
                TotpCredentialId.of(entity.getId()),
                UserId.of(entity.getUserId()),
                EncryptedTotpSecret.of(entity.getEncryptedSecret()),
                entity.getStatus(),
                entity.getCreatedAt(),
                entity.getActivatedAt());
    }
}
