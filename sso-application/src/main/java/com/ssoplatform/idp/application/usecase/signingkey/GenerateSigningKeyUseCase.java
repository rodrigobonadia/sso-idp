package com.ssoplatform.idp.application.usecase.signingkey;

import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.port.out.GeneratedKeyPair;
import com.ssoplatform.idp.application.port.out.PrivateKeyEncryptor;
import com.ssoplatform.idp.application.port.out.SigningKeyPairGenerator;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.KeyId;
import com.ssoplatform.idp.domain.signingkey.PublicKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.util.Base64;
import java.util.Objects;

/**
 * Generates a brand-new RSA signing key for a tenant and makes it the tenant's current key,
 * retiring whatever key was current before (if any) - see {@code architecture_decisions.md} for
 * why rotation works this way: a new key always takes over signing immediately, and the previous
 * one keeps being published in the JWKS document purely so already-issued tokens stay verifiable.
 *
 * <p>Invoked only through the manual {@code POST /internal/signing-keys} endpoint (Phase 3.2 has
 * no automatic rotation schedule) - see {@code architecture_decisions.md} for that decision too.
 */
public class GenerateSigningKeyUseCase {

    private final TenantRepository tenantRepository;
    private final SigningKeyRepository signingKeyRepository;
    private final SigningKeyPairGenerator keyPairGenerator;
    private final PrivateKeyEncryptor privateKeyEncryptor;

    public GenerateSigningKeyUseCase(
            TenantRepository tenantRepository,
            SigningKeyRepository signingKeyRepository,
            SigningKeyPairGenerator keyPairGenerator,
            PrivateKeyEncryptor privateKeyEncryptor) {
        this.tenantRepository = Objects.requireNonNull(tenantRepository, "tenantRepository must not be null");
        this.signingKeyRepository =
                Objects.requireNonNull(signingKeyRepository, "signingKeyRepository must not be null");
        this.keyPairGenerator = Objects.requireNonNull(keyPairGenerator, "keyPairGenerator must not be null");
        this.privateKeyEncryptor =
                Objects.requireNonNull(privateKeyEncryptor, "privateKeyEncryptor must not be null");
    }

    public GenerateSigningKeyResult execute(GenerateSigningKeyCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());

        Objects.requireNonNull(tenantId, "tenantId must not be null");
        tenantRepository.findById(tenantId).orElseThrow(() -> new TenantNotFoundException(command.tenantId()));

        signingKeyRepository.findCurrentByTenantId(tenantId).ifPresent(currentKey -> {
            currentKey.retire();
            signingKeyRepository.save(currentKey);
        });

        GeneratedKeyPair keyPair = keyPairGenerator.generate();
        PublicKeyMaterial publicKey = PublicKeyMaterial.of(Base64.getEncoder().encodeToString(keyPair.publicKeyDer()));
        EncryptedPrivateKeyMaterial encryptedPrivateKey = privateKeyEncryptor.encrypt(keyPair.privateKeyDer());

        SigningKey newKey = SigningKey.generate(tenantId, KeyId.generate(), publicKey, encryptedPrivateKey);
        SigningKey saved = signingKeyRepository.save(newKey);

        return new GenerateSigningKeyResult(saved.kid().value(), saved.tenantId().value(), saved.createdAt());
    }
}
