package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.MfaEnrollmentNotFoundException;
import com.ssoplatform.idp.application.port.out.RecoveryCodeHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.application.port.out.TotpCodeVerifier;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpSecretEncryptor;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ConfirmTotpEnrollmentUseCaseTest {

    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    @Mock
    private TotpSecretEncryptor totpSecretEncryptor;

    @Mock
    private TotpCodeVerifier totpCodeVerifier;

    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    @Mock
    private RecoveryCodeHasher recoveryCodeHasher;

    private ConfirmTotpEnrollmentUseCase useCase;
    private UserId userId;
    private byte[] rawSecretBytes;
    private EncryptedTotpSecret encryptedSecret;

    @BeforeEach
    void setUp() {
        useCase = new ConfirmTotpEnrollmentUseCase(
                totpCredentialRepository, totpSecretEncryptor, totpCodeVerifier, recoveryCodeRepository, recoveryCodeHasher);
        userId = UserId.generate();
        rawSecretBytes = "raw-secret-bytes".getBytes();
        encryptedSecret = EncryptedTotpSecret.of("Y2lwaGVydGV4dA==");
    }

    @Test
    void activatesThePendingCredentialAndIssuesTenRecoveryCodesOnACorrectCode() {
        TotpCredential pending = TotpCredential.enroll(userId, encryptedSecret, Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));
        when(totpSecretEncryptor.decrypt(encryptedSecret)).thenReturn(rawSecretBytes);
        when(totpCodeVerifier.verify(eq(rawSecretBytes), any())).thenReturn(true);
        when(recoveryCodeHasher.hash(any())).thenReturn(RecoveryCodeHash.of("$2a$12$somehash"));
        when(recoveryCodeRepository.saveAll(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ConfirmTotpEnrollmentResult result = useCase.execute(new ConfirmTotpEnrollmentCommand(userId.value(), "123456"));

        assertThat(result.recoveryCodes()).hasSize(10);
        assertThat(result.recoveryCodes()).doesNotHaveDuplicates();
        assertThat(pending.isActive()).isTrue();
        verify(totpCredentialRepository).save(pending);
        verify(recoveryCodeRepository).deleteAllByUserId(userId);
        ArgumentCaptor<List> savedCodes = ArgumentCaptor.forClass(List.class);
        verify(recoveryCodeRepository).saveAll(savedCodes.capture());
        assertThat(savedCodes.getValue()).hasSize(10);
    }

    @Test
    void rejectsAWrongCodeAndDoesNotActivateOrIssueRecoveryCodes() {
        TotpCredential pending = TotpCredential.enroll(userId, encryptedSecret, Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));
        when(totpSecretEncryptor.decrypt(encryptedSecret)).thenReturn(rawSecretBytes);
        when(totpCodeVerifier.verify(eq(rawSecretBytes), any())).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(new ConfirmTotpEnrollmentCommand(userId.value(), "000000")))
                .isInstanceOf(InvalidMfaCodeException.class);

        assertThat(pending.isActive()).isFalse();
        verify(totpCredentialRepository, never()).save(any());
        verify(recoveryCodeRepository, never()).saveAll(any());
    }

    @Test
    void rejectsConfirmationWhenNoPendingEnrollmentExists() {
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new ConfirmTotpEnrollmentCommand(userId.value(), "123456")))
                .isInstanceOf(MfaEnrollmentNotFoundException.class);
    }

    @Test
    void rejectsConfirmationWhenTheCredentialIsAlreadyActive() {
        TotpCredential active = TotpCredential.enroll(userId, encryptedSecret, Instant.now());
        active.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(active));

        assertThatThrownBy(() -> useCase.execute(new ConfirmTotpEnrollmentCommand(userId.value(), "123456")))
                .isInstanceOf(MfaEnrollmentNotFoundException.class);
    }
}
