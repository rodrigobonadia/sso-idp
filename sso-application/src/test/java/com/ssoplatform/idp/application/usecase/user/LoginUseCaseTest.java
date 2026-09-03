package com.ssoplatform.idp.application.usecase.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.AccountDisabledException;
import com.ssoplatform.idp.application.exception.AccountLockedException;
import com.ssoplatform.idp.application.exception.AccountNotVerifiedException;
import com.ssoplatform.idp.application.exception.InvalidCredentialsException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.MfaMethod;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class LoginUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final HashedPassword PASSWORD_HASH = HashedPassword.of("$2a$10$somehashvalue");

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordHasher passwordHasher;

    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    @Mock
    private EmailOtpCredentialRepository emailOtpCredentialRepository;

    @Mock
    private EmailOtpCodeRepository emailOtpCodeRepository;

    @Mock
    private EmailOtpCodeHasher emailOtpCodeHasher;

    @Mock
    private EmailSender emailSender;

    @Mock
    private MfaChallengeRepository mfaChallengeRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    private LoginUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new LoginUseCase(
                userRepository,
                passwordHasher,
                totpCredentialRepository,
                emailOtpCredentialRepository,
                emailOtpCodeRepository,
                emailOtpCodeHasher,
                emailSender,
                mfaChallengeRepository,
                verificationTokenHasher);
    }

    private User activeUser() {
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                PASSWORD_HASH);
        user.verifyEmail();
        return user;
    }

    @Test
    void authenticatesAnActiveUserWithTheCorrectPasswordAndResetsFailedAttempts() {
        User user = activeUser();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);
        when(userRepository.save(user)).thenReturn(user);
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());
        when(emailOtpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());

        LoginOutcome outcome =
                useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd"));

        assertThat(outcome).isInstanceOf(LoginOutcome.Authenticated.class);
        LoginResult result = ((LoginOutcome.Authenticated) outcome).result();
        assertThat(result.userId()).isEqualTo(user.id().value());
        assertThat(result.tenantId()).isEqualTo(TENANT_ID.value());
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(user.failedLoginAttempts()).isZero();
        verify(userRepository).save(user);
        verify(mfaChallengeRepository, never()).save(any());
        verify(emailSender, never()).sendMfaEmailOtpCode(any(), any());
    }

    @Test
    void issuesAnMfaChallengeInsteadOfAuthenticatingWhenTheUserHasAnActiveTotpCredential() {
        User user = activeUser();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);
        when(userRepository.save(user)).thenReturn(user);
        TotpCredential activeCredential =
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("ciphertext"), Instant.now());
        activeCredential.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(activeCredential));
        when(verificationTokenHasher.hash(any())).thenReturn(TokenHash.of("some-hash"));

        LoginOutcome outcome =
                useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd"));

        assertThat(outcome).isInstanceOf(LoginOutcome.MfaChallengeIssued.class);
        LoginOutcome.MfaChallengeIssued issued = (LoginOutcome.MfaChallengeIssued) outcome;
        assertThat(issued.challengeToken()).isNotBlank();
        assertThat(issued.method()).isEqualTo(MfaMethod.TOTP);
        verify(mfaChallengeRepository).save(any());
        verify(emailOtpCredentialRepository, never()).findByUserId(any());
        verify(emailSender, never()).sendMfaEmailOtpCode(any(), any());
        // The password check and account-status transition already ran (failed attempts reset,
        // status validated) - only session establishment is deferred, not authentication itself.
        assertThat(user.failedLoginAttempts()).isZero();
    }

    @Test
    void issuesAnMfaChallengeWithEmailOtpMethodAndSendsACodeWhenTheUserHasAnActiveEmailOtpCredential() {
        User user = activeUser();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);
        when(userRepository.save(user)).thenReturn(user);
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());
        EmailOtpCredential activeEmailOtpCredential = EmailOtpCredential.enable(user.id(), Instant.now());
        activeEmailOtpCredential.activate(Instant.now());
        when(emailOtpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(activeEmailOtpCredential));
        when(verificationTokenHasher.hash(any())).thenReturn(TokenHash.of("some-hash"));
        when(emailOtpCodeHasher.hash(any())).thenReturn(EmailOtpCodeHash.of("some-code-hash"));

        LoginOutcome outcome =
                useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd"));

        assertThat(outcome).isInstanceOf(LoginOutcome.MfaChallengeIssued.class);
        LoginOutcome.MfaChallengeIssued issued = (LoginOutcome.MfaChallengeIssued) outcome;
        assertThat(issued.challengeToken()).isNotBlank();
        assertThat(issued.method()).isEqualTo(MfaMethod.EMAIL_OTP);
        verify(mfaChallengeRepository).save(any());
        verify(emailOtpCodeRepository).save(any());
        verify(emailSender).sendMfaEmailOtpCode(eq(user.email()), any());
        assertThat(user.failedLoginAttempts()).isZero();
    }

    @Test
    void doesNotIssueAChallengeForAPendingUnconfirmedTotpCredential() {
        User user = activeUser();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);
        when(userRepository.save(user)).thenReturn(user);
        TotpCredential pendingCredential =
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("ciphertext"), Instant.now());
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(pendingCredential));
        when(emailOtpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());

        LoginOutcome outcome =
                useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd"));

        assertThat(outcome).isInstanceOf(LoginOutcome.Authenticated.class);
        verify(mfaChallengeRepository, never()).save(any());
    }

    @Test
    void doesNotIssueAChallengeForAPendingUnconfirmedEmailOtpCredential() {
        User user = activeUser();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);
        when(userRepository.save(user)).thenReturn(user);
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());
        EmailOtpCredential pendingCredential = EmailOtpCredential.enable(user.id(), Instant.now());
        when(emailOtpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(pendingCredential));

        LoginOutcome outcome =
                useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd"));

        assertThat(outcome).isInstanceOf(LoginOutcome.Authenticated.class);
        verify(mfaChallengeRepository, never()).save(any());
        verify(emailSender, never()).sendMfaEmailOtpCode(any(), any());
    }

    @Test
    void rejectsAnUnknownEmailWithTheGenericInvalidCredentialsExceptionAndDoesNotTouchAnyUser() {
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("nobody@example.com")))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new LoginCommand(TENANT_ID.value(), "nobody@example.com", "whatever")))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsAMalformedEmailWithTheGenericInvalidCredentialsExceptionRatherThanALeakingValidationError() {
        assertThatThrownBy(() -> useCase.execute(new LoginCommand(TENANT_ID.value(), "not-an-email", "whatever")))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).findByTenantIdAndEmail(any(), any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsAWeakShapedPasswordAsAnOrdinaryWrongPasswordRatherThanAStrengthPolicyError() {
        User user = activeUser();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(false);

        // "short" would fail RawPassword.of()'s strength policy (min length, character classes);
        // the use case must never run the login candidate through that policy - it should simply
        // be treated as a wrong password, not rejected with a WeakPasswordException.
        assertThatThrownBy(() -> useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "short")))
                .isInstanceOf(InvalidCredentialsException.class);

        assertThat(user.failedLoginAttempts()).isEqualTo(1);
    }

    @Test
    void rejectsAWrongPasswordWithTheGenericInvalidCredentialsExceptionAndRecordsTheFailedAttempt() {
        User user = activeUser();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(false);

        assertThatThrownBy(
                        () -> useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "wrong")))
                .isInstanceOf(InvalidCredentialsException.class);

        assertThat(user.failedLoginAttempts()).isEqualTo(1);
        verify(userRepository).save(user);
    }

    @Test
    void rejectsTheCorrectPasswordForAnAccountPendingVerification() {
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                PASSWORD_HASH);
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(
                        new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd")))
                .isInstanceOf(AccountNotVerifiedException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsTheCorrectPasswordForALockedAccount() {
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                PASSWORD_HASH);
        user.lock();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(
                        new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd")))
                .isInstanceOf(AccountLockedException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsTheCorrectPasswordForADisabledAccount() {
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                PASSWORD_HASH);
        user.disable();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(
                        new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd")))
                .isInstanceOf(AccountDisabledException.class);

        verify(userRepository, never()).save(any());
    }
}
