package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.signingkey.SigningKeyStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA representation of a signing key row, scoped by {@code tenant_id} - mirrors {@link
 * OAuthClientJpaEntity}'s reasoning. {@code public_key} and {@code encrypted_private_key} are each
 * a Base64 string ({@code TEXT}, since a 4096-bit RSA key's DER encoding comfortably exceeds a
 * short {@code VARCHAR}) - the private key column always holds already-encrypted ciphertext (see
 * {@code AesGcmPrivateKeyEncryptorAdapter}), never plaintext key material.
 */
@Entity
@Table(name = "signing_keys")
public class SigningKeyJpaEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(name = "kid", nullable = false, length = 64)
    private String kid;

    @Column(name = "algorithm", nullable = false, length = 20)
    private String algorithm;

    @Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
    private String publicKey;

    @Column(name = "encrypted_private_key", nullable = false, columnDefinition = "TEXT")
    private String encryptedPrivateKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private SigningKeyStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected SigningKeyJpaEntity() {
        // required by JPA
    }

    public SigningKeyJpaEntity(
            UUID id,
            UUID tenantId,
            String kid,
            String algorithm,
            String publicKey,
            String encryptedPrivateKey,
            SigningKeyStatus status,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.kid = kid;
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.status = status;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getKid() {
        return kid;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public SigningKeyStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
