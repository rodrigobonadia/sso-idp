package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.MfaAlreadyEnabledException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpSecretEncryptor;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class EnrollTotpUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();

    @Mock
    private UserRepository userRepository;

    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    @Mock
    private EmailOtpCredentialRepository emailOtpCredentialRepository;

    @Mock
    private TotpSecretEncryptor totpSecretEncryptor;

    private EnrollTotpUseCase useCase;
    private User user;

    @BeforeEach
    void setUp() {
        useCase = new EnrollTotpUseCase(
                userRepository, totpCredentialRepository, emailOtpCredentialRepository, totpSecretEncryptor);
        user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
    }

    @Test
    void startsEnrollmentAndReturnsTheSecretAndOtpauthUriWhenTheUserHasNoExistingCredential() {
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());
        when(totpSecretEncryptor.encrypt(any())).thenReturn(EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="));

        EnrollTotpResult result = useCase.execute(new EnrollTotpCommand(user.id().value()));

        assertThat(result.secretBase32()).hasSize(32); // 20 bytes * 8 bits / 5 bits-per-symbol
        assertThat(result.otpauthUri()).startsWith("otpauth://totp/");
        assertThat(result.otpauthUri()).contains("secret=" + result.secretBase32());
        assertThat(result.otpauthUri()).contains("someone%40example.com");

        ArgumentCaptor<TotpCredential> saved = ArgumentCaptor.forClass(TotpCredential.class);
        verify(totpCredentialRepository).save(saved.capture());
        assertThat(saved.getValue().userId()).isEqualTo(user.id());
        assertThat(saved.getValue().isActive()).isFalse();
    }

    @Test
    void replacesAnAbandonedPendingEnrollmentWithoutComplaint() {
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        TotpCredential pending =
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("b2xkLWNpcGhlcnRleHQ="), Instant.now());
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(pending));
        when(totpSecretEncryptor.encrypt(any())).thenReturn(EncryptedTotpSecret.of("bmV3LWNpcGhlcnRleHQ="));

        useCase.execute(new EnrollTotpCommand(user.id().value()));

        verify(totpCredentialRepository).deleteByUserId(user.id());
        verify(totpCredentialRepository).save(any());
    }

    @Test
    void rejectsEnrollmentWhenAnActiveTotpCredentialAlreadyExists() {
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        TotpCredential active =
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("YWN0aXZlLWNpcGhlcnRleHQ="), Instant.now());
        active.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(active));

        assertThatThrownBy(() -> useCase.execute(new EnrollTotpCommand(user.id().value())))
                .isInstanceOf(MfaAlreadyEnabledException.class);

        verify(totpCredentialRepository, never()).deleteByUserId(any());
        verify(totpCredentialRepository, never()).save(any());
    }

    /** Phase 4.2: the reverse-method check - TOTP enrollment must also refuse when e-mail OTP,
     * not TOTP, is the user's currently active method (a user may have at most one). */
    @Test
    void rejectsEnrollmentWhenAnActiveEmailOtpCredentialAlreadyExists() {
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());
        EmailOtpCredential activeEmailOtp = EmailOtpCredential.enable(user.id(), Instant.now());
        activeEmailOtp.activate(Instant.now());
        when(emailOtpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(activeEmailOtp));

        assertThatThrownBy(() -> useCase.execute(new EnrollTotpCommand(user.id().value())))
                .isInstanceOf(MfaAlreadyEnabledException.class);

        verify(totpCredentialRepository, never()).deleteByUserId(any());
        verify(totpCredentialRepository, never()).save(any());
    }

    @Test
    void surfacesUserNotFoundForAnUnknownUserId() {
        when(userRepository.findById(user.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new EnrollTotpCommand(user.id().value())))
                .isInstanceOf(UserNotFoundException.class);

        verify(totpCredentialRepository, never()).findByUserId(any());
    }
}
