package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class EmailOtpCredentialTest {

    private final UserId userId = UserId.generate();

    @Test
    void enableProducesAPendingActivationCredential() {
        EmailOtpCredential credential = EmailOtpCredential.enable(userId, Instant.now());

        assertThat(credential.id()).isNotNull();
        assertThat(credential.userId()).isEqualTo(userId);
        assertThat(credential.status()).isEqualTo(EmailOtpCredentialStatus.PENDING_ACTIVATION);
        assertThat(credential.isActive()).isFalse();
        assertThat(credential.activatedAt()).isNull();
    }

    @Test
    void enableRejectsNullArguments() {
        assertThatThrownBy(() -> EmailOtpCredential.enable(null, Instant.now()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> EmailOtpCredential.enable(userId, null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    void activateTransitionsFromPendingActivationToActive() {
        EmailOtpCredential credential = EmailOtpCredential.enable(userId, Instant.now());
        Instant activatedAt = Instant.now();

        credential.activate(activatedAt);

        assertThat(credential.status()).isEqualTo(EmailOtpCredentialStatus.ACTIVE);
        assertThat(credential.isActive()).isTrue();
        assertThat(credential.activatedAt()).isEqualTo(activatedAt);
    }

    @Test
    void activatingAnAlreadyActiveCredentialThrows() {
        EmailOtpCredential credential = EmailOtpCredential.enable(userId, Instant.now());
        credential.activate(Instant.now());

        assertThatThrownBy(() -> credential.activate(Instant.now()))
                .isInstanceOf(EmailOtpCredentialStateException.class);
    }

    @Test
    void reconstituteRestoresAllFields() {
        EmailOtpCredentialId id = EmailOtpCredentialId.generate();
        Instant createdAt = Instant.now().minusSeconds(3600);
        Instant activatedAt = Instant.now().minusSeconds(60);

        EmailOtpCredential credential = EmailOtpCredential.reconstitute(
                id, userId, EmailOtpCredentialStatus.ACTIVE, createdAt, activatedAt);

        assertThat(credential.id()).isEqualTo(id);
        assertThat(credential.userId()).isEqualTo(userId);
        assertThat(credential.status()).isEqualTo(EmailOtpCredentialStatus.ACTIVE);
        assertThat(credential.createdAt()).isEqualTo(createdAt);
        assertThat(credential.activatedAt()).isEqualTo(activatedAt);
    }

    @Test
    void equalityIsBasedOnId() {
        EmailOtpCredential credential1 = EmailOtpCredential.enable(userId, Instant.now());
        EmailOtpCredential credential2 = EmailOtpCredential.reconstitute(
                credential1.id(), userId, EmailOtpCredentialStatus.PENDING_ACTIVATION, credential1.createdAt(), null);

        assertThat(credential1).isEqualTo(credential2);
        assertThat(credential1).hasSameHashCodeAs(credential2);
    }
}
