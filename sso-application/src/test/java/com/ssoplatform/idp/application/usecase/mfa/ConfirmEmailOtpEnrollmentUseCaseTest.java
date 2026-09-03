package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.MfaEnrollmentNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.RecoveryCodeHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import com.ssoplatform.idp.domain.user.UserId;
import java.time.Duration;
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
class ConfirmEmailOtpEnrollmentUseCaseTest {

    @Mock
    private EmailOtpCredentialRepository emailOtpCredentialRepository;

    @Mock
    private EmailOtpCodeRepository emailOtpCodeRepository;

    @Mock
    private EmailOtpCodeHasher emailOtpCodeHasher;

    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    @Mock
    private RecoveryCodeHasher recoveryCodeHasher;

    private ConfirmEmailOtpEnrollmentUseCase useCase;
    private UserId userId;
    private EmailOtpCodeHash codeHash;

    @BeforeEach
    void setUp() {
        useCase = new ConfirmEmailOtpEnrollmentUseCase(
                emailOtpCredentialRepository,
                emailOtpCodeRepository,
                emailOtpCodeHasher,
                recoveryCodeRepository,
                recoveryCodeHasher);
        userId = UserId.generate();
        codeHash = EmailOtpCodeHash.of("$2a$12$somehash");
    }

    @Test
    void activatesThePendingCredentialAndIssuesTenRecoveryCodesOnACorrectCode() {
        EmailOtpCredential pending = EmailOtpCredential.enable(userId, Instant.now());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));
        EmailOtpCode code =
                EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));
        when(emailOtpCodeRepository.findLatestByUserIdAndPurpose(userId, EmailOtpPurpose.ENROLLMENT_CONFIRMATION))
                .thenReturn(Optional.of(code));
        when(emailOtpCodeHasher.matches(any(), any())).thenReturn(true);
        when(recoveryCodeHasher.hash(any())).thenReturn(RecoveryCodeHash.of("$2a$12$somehash"));
        when(recoveryCodeRepository.saveAll(any())).thenAnswer(invocation -> invocation.getArgument(0));

        ConfirmEmailOtpEnrollmentResult result =
                useCase.execute(new ConfirmEmailOtpEnrollmentCommand(userId.value(), "123456"));

        assertThat(result.recoveryCodes()).hasSize(10);
        assertThat(result.recoveryCodes()).doesNotHaveDuplicates();
        assertThat(pending.isActive()).isTrue();
        assertThat(code.isConsumed()).isTrue();
        verify(emailOtpCredentialRepository).save(pending);
        verify(emailOtpCodeRepository).save(code);
        verify(recoveryCodeRepository).deleteAllByUserId(userId);
        ArgumentCaptor<List> savedCodes = ArgumentCaptor.forClass(List.class);
        verify(recoveryCodeRepository).saveAll(savedCodes.capture());
        assertThat(savedCodes.getValue()).hasSize(10);
    }

    @Test
    void rejectsAWrongCodeRecordsTheFailedAttemptAndDoesNotActivateOrIssueRecoveryCodes() {
        EmailOtpCredential pending = EmailOtpCredential.enable(userId, Instant.now());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));
        EmailOtpCode code =
                EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), Duration.ofMinutes(5));
        when(emailOtpCodeRepository.findLatestByUserIdAndPurpose(userId, EmailOtpPurpose.ENROLLMENT_CONFIRMATION))
                .thenReturn(Optional.of(code));
        when(emailOtpCodeHasher.matches(any(), any())).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(new ConfirmEmailOtpEnrollmentCommand(userId.value(), "000000")))
                .isInstanceOf(InvalidMfaCodeException.class);

        assertThat(pending.isActive()).isFalse();
        assertThat(code.failedAttempts()).isEqualTo(1);
        verify(emailOtpCodeRepository).save(code);
        verify(emailOtpCredentialRepository, never()).save(any());
        verify(recoveryCodeRepository, never()).saveAll(any());
    }

    @Test
    void rejectsConfirmationWhenNoPendingEnrollmentExists() {
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new ConfirmEmailOtpEnrollmentCommand(userId.value(), "123456")))
                .isInstanceOf(MfaEnrollmentNotFoundException.class);
    }

    @Test
    void rejectsConfirmationWhenTheCredentialIsAlreadyActive() {
        EmailOtpCredential active = EmailOtpCredential.enable(userId, Instant.now());
        active.activate(Instant.now());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(active));

        assertThatThrownBy(() -> useCase.execute(new ConfirmEmailOtpEnrollmentCommand(userId.value(), "123456")))
                .isInstanceOf(MfaEnrollmentNotFoundException.class);
    }

    @Test
    void rejectsConfirmationWhenNoConfirmationCodeWasEverIssued() {
        EmailOtpCredential pending = EmailOtpCredential.enable(userId, Instant.now());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));
        when(emailOtpCodeRepository.findLatestByUserIdAndPurpose(userId, EmailOtpPurpose.ENROLLMENT_CONFIRMATION))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new ConfirmEmailOtpEnrollmentCommand(userId.value(), "123456")))
                .isInstanceOf(MfaEnrollmentNotFoundException.class);
    }
}
