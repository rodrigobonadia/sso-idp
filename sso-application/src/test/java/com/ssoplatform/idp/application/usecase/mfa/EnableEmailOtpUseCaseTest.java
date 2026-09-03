package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.MfaAlreadyEnabledException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EnableEmailOtpUseCaseTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailOtpCredentialRepository emailOtpCredentialRepository;

    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    @Mock
    private EmailOtpCodeRepository emailOtpCodeRepository;

    @Mock
    private EmailOtpCodeHasher emailOtpCodeHasher;

    @Mock
    private EmailSender emailSender;

    private EnableEmailOtpUseCase useCase;
    private User user;
    private UserId userId;

    @BeforeEach
    void setUp() {
        useCase = new EnableEmailOtpUseCase(
                userRepository,
                emailOtpCredentialRepository,
                totpCredentialRepository,
                emailOtpCodeRepository,
                emailOtpCodeHasher,
                emailSender);
        user = User.register(
                TenantId.generate(),
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
        userId = user.id();
    }

    @Test
    void enablesEmailOtpAndSendsAMaskedConfirmationCodeWhenNoOtherMethodIsActive() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(emailOtpCodeHasher.hash(any())).thenReturn(EmailOtpCodeHash.of("$2a$12$somehash"));

        EnableEmailOtpResult result = useCase.execute(new EnableEmailOtpCommand(userId.value()));

        assertThat(result.maskedEmail()).isEqualTo("s***e@example.com");
        verify(emailOtpCredentialRepository).save(any());
        verify(emailOtpCodeRepository).save(any());
        verify(emailSender).sendMfaEmailOtpCode(eq(user.email()), any());
    }

    @Test
    void replacesAStillPendingCredentialAndItsStaleCodeWhenReRunWhileNotYetConfirmed() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(emailOtpCodeHasher.hash(any())).thenReturn(EmailOtpCodeHash.of("$2a$12$somehash"));

        useCase.execute(new EnableEmailOtpCommand(userId.value()));

        verify(emailOtpCredentialRepository).deleteByUserId(userId);
        verify(emailOtpCodeRepository).deleteByUserIdAndPurpose(userId, EmailOtpPurpose.ENROLLMENT_CONFIRMATION);
    }

    @Test
    void rejectsEnablingWhenAnActiveTotpCredentialAlreadyExists() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        TotpCredential activeTotp =
                TotpCredential.enroll(userId, EncryptedTotpSecret.of("ciphertext"), Instant.now());
        activeTotp.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(activeTotp));

        assertThatThrownBy(() -> useCase.execute(new EnableEmailOtpCommand(userId.value())))
                .isInstanceOf(MfaAlreadyEnabledException.class);

        verify(emailOtpCredentialRepository, never()).save(any());
        verify(emailSender, never()).sendMfaEmailOtpCode(any(), any());
    }

    @Test
    void rejectsEnablingWhenAnActiveEmailOtpCredentialAlreadyExists() {
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        EmailOtpCredential activeEmailOtp = EmailOtpCredential.enable(userId, Instant.now());
        activeEmailOtp.activate(Instant.now());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(activeEmailOtp));

        assertThatThrownBy(() -> useCase.execute(new EnableEmailOtpCommand(userId.value())))
                .isInstanceOf(MfaAlreadyEnabledException.class);

        verify(emailOtpCredentialRepository, never()).save(any());
        verify(emailSender, never()).sendMfaEmailOtpCode(any(), any());
    }

    @Test
    void rejectsEnablingForAnUnknownUser() {
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new EnableEmailOtpCommand(userId.value())))
                .isInstanceOf(UserNotFoundException.class);
    }
}
