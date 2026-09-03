package com.ssoplatform.idp.domain.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class TotpCredentialTest {

    private final UserId userId = UserId.generate();
    private final EncryptedTotpSecret encryptedSecret = EncryptedTotpSecret.of("Y2lwaGVydGV4dA==");

    @Test
    void enrollProducesAPendingActivationCredential() {
        TotpCredential credential = TotpCredential.enroll(userId, encryptedSecret, Instant.now());

        assertThat(credential.id()).isNotNull();
        assertThat(credential.userId()).isEqualTo(userId);
        assertThat(credential.encryptedSecret()).isEqualTo(encryptedSecret);
        assertThat(credential.status()).isEqualTo(TotpCredentialStatus.PENDING_ACTIVATION);
        assertThat(credential.isActive()).isFalse();
        assertThat(credential.activatedAt()).isNull();
    }

    @Test
    void enrollRejectsNullArguments() {
        assertThatThrownBy(() -> TotpCredential.enroll(null, encryptedSecret, Instant.now()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> TotpCredential.enroll(userId, null, Instant.now()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> TotpCredential.enroll(userId, encryptedSecret, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void activateTransitionsFromPendingActivationToActive() {
        TotpCredential credential = TotpCredential.enroll(userId, encryptedSecret, Instant.now());
        Instant activatedAt = Instant.now();

        credential.activate(activatedAt);

        assertThat(credential.status()).isEqualTo(TotpCredentialStatus.ACTIVE);
        assertThat(credential.isActive()).isTrue();
        assertThat(credential.activatedAt()).isEqualTo(activatedAt);
    }

    @Test
    void activatingAnAlreadyActiveCredentialThrows() {
        TotpCredential credential = TotpCredential.enroll(userId, encryptedSecret, Instant.now());
        credential.activate(Instant.now());

        assertThatThrownBy(() -> credential.activate(Instant.now())).isInstanceOf(TotpCredentialStateException.class);
    }

    @Test
    void reconstituteRestoresAllFields() {
        TotpCredentialId id = TotpCredentialId.generate();
        Instant createdAt = Instant.now().minusSeconds(3600);
        Instant activatedAt = Instant.now().minusSeconds(60);

        TotpCredential credential = TotpCredential.reconstitute(
                id, userId, encryptedSecret, TotpCredentialStatus.ACTIVE, createdAt, activatedAt);

        assertThat(credential.id()).isEqualTo(id);
        assertThat(credential.userId()).isEqualTo(userId);
        assertThat(credential.encryptedSecret()).isEqualTo(encryptedSecret);
        assertThat(credential.status()).isEqualTo(TotpCredentialStatus.ACTIVE);
        assertThat(credential.createdAt()).isEqualTo(createdAt);
        assertThat(credential.activatedAt()).isEqualTo(activatedAt);
    }

    @Test
    void equalityIsBasedOnId() {
        TotpCredential credential1 = TotpCredential.enroll(userId, encryptedSecret, Instant.now());
        TotpCredential credential2 = TotpCredential.reconstitute(
                credential1.id(),
                userId,
                encryptedSecret,
                TotpCredentialStatus.PENDING_ACTIVATION,
                credential1.createdAt(),
                null);

        assertThat(credential1).isEqualTo(credential2);
        assertThat(credential1).hasSameHashCodeAs(credential2);
    }
}
