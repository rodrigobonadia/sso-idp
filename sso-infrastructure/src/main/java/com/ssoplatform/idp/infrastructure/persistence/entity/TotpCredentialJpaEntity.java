package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.mfa.TotpCredentialStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** JPA representation of a user's TOTP credential row. {@code user_id} is unique: exactly one
 * credential (pending or active) can exist per user at a time. */
@Entity
@Table(name = "totp_credentials")
public class TotpCredentialJpaEntity {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;

    @Column(name = "encrypted_secret", nullable = false, columnDefinition = "TEXT")
    private String encryptedSecret;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private TotpCredentialStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "activated_at")
    private Instant activatedAt;

    protected TotpCredentialJpaEntity() {
        // required by JPA
    }

    public TotpCredentialJpaEntity(
            UUID id,
            UUID userId,
            String encryptedSecret,
            TotpCredentialStatus status,
            Instant createdAt,
            Instant activatedAt) {
        this.id = id;
        this.userId = userId;
        this.encryptedSecret = encryptedSecret;
        this.status = status;
        this.createdAt = createdAt;
        this.activatedAt = activatedAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEncryptedSecret() {
        return encryptedSecret;
    }

    public TotpCredentialStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getActivatedAt() {
        return activatedAt;
    }
}
