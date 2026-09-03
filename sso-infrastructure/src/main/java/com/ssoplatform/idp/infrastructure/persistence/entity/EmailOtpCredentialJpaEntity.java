package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.mfa.EmailOtpCredentialStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** JPA representation of a user's e-mail OTP credential row (Phase 4.2). {@code user_id} is
 * unique: exactly one credential (pending or active) can exist per user at a time. Mirrors {@link
 * TotpCredentialJpaEntity} exactly, minus the secret column - there is nothing to encrypt here. */
@Entity
@Table(name = "email_otp_credentials")
public class EmailOtpCredentialJpaEntity {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false, unique = true)
    private UUID userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private EmailOtpCredentialStatus status;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "activated_at")
    private Instant activatedAt;

    protected EmailOtpCredentialJpaEntity() {
        // required by JPA
    }

    public EmailOtpCredentialJpaEntity(
            UUID id, UUID userId, EmailOtpCredentialStatus status, Instant createdAt, Instant activatedAt) {
        this.id = id;
        this.userId = userId;
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

    public EmailOtpCredentialStatus getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getActivatedAt() {
        return activatedAt;
    }
}
