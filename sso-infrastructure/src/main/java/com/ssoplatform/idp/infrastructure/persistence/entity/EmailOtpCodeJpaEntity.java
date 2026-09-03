package com.ssoplatform.idp.infrastructure.persistence.entity;

import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** JPA representation of a single e-mail OTP code instance (Phase 4.2) - either confirming
 * enrollment or satisfying one specific login challenge. {@code mfa_challenge_id} is null for an
 * {@code ENROLLMENT_CONFIRMATION} row. */
@Entity
@Table(name = "email_otp_codes")
public class EmailOtpCodeJpaEntity {

    @Id
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "purpose", nullable = false, length = 30)
    private EmailOtpPurpose purpose;

    @Column(name = "mfa_challenge_id")
    private UUID mfaChallengeId;

    @Column(name = "code_hash", nullable = false, length = 255)
    private String codeHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected EmailOtpCodeJpaEntity() {
        // required by JPA
    }

    public EmailOtpCodeJpaEntity(
            UUID id,
            UUID userId,
            EmailOtpPurpose purpose,
            UUID mfaChallengeId,
            String codeHash,
            Instant expiresAt,
            Instant consumedAt,
            int failedAttempts,
            Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.purpose = purpose;
        this.mfaChallengeId = mfaChallengeId;
        this.codeHash = codeHash;
        this.expiresAt = expiresAt;
        this.consumedAt = consumedAt;
        this.failedAttempts = failedAttempts;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getUserId() {
        return userId;
    }

    public EmailOtpPurpose getPurpose() {
        return purpose;
    }

    public UUID getMfaChallengeId() {
        return mfaChallengeId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
