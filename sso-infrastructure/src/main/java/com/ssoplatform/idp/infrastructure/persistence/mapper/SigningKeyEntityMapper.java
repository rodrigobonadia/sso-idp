package com.ssoplatform.idp.infrastructure.persistence.mapper;

import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.KeyId;
import com.ssoplatform.idp.domain.signingkey.PublicKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.signingkey.SigningKeyId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.infrastructure.persistence.entity.SigningKeyJpaEntity;

/** Translates between the {@link SigningKey} domain entity and its JPA row. */
public final class SigningKeyEntityMapper {

    private SigningKeyEntityMapper() {}

    public static SigningKeyJpaEntity toEntity(SigningKey key) {
        return new SigningKeyJpaEntity(
                key.id().value(),
                key.tenantId().value(),
                key.kid().value(),
                key.algorithm(),
                key.publicKey().value(),
                key.encryptedPrivateKey().value(),
                key.status(),
                key.createdAt());
    }

    public static SigningKey toDomain(SigningKeyJpaEntity entity) {
        return SigningKey.reconstitute(
                SigningKeyId.of(entity.getId()),
                TenantId.of(entity.getTenantId()),
                KeyId.of(entity.getKid()),
                entity.getAlgorithm(),
                PublicKeyMaterial.of(entity.getPublicKey()),
                EncryptedPrivateKeyMaterial.of(entity.getEncryptedPrivateKey()),
                entity.getStatus(),
                entity.getCreatedAt());
    }
}
