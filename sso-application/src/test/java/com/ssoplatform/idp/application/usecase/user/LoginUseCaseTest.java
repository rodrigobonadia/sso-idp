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
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.User;
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

    private LoginUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new LoginUseCase(userRepository, passwordHasher);
    }

    @Test
    void authenticatesAnActiveUserWithTheCorrectPasswordAndResetsFailedAttempts() {
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                PASSWORD_HASH);
        user.verifyEmail();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(passwordHasher.matches(any(String.class), eq(PASSWORD_HASH))).thenReturn(true);
        when(userRepository.save(user)).thenReturn(user);

        LoginResult result =
                useCase.execute(new LoginCommand(TENANT_ID.value(), "someone@example.com", "Str0ng!Passw0rd"));

        assertThat(result.userId()).isEqualTo(user.id().value());
        assertThat(result.tenantId()).isEqualTo(TENANT_ID.value());
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(user.failedLoginAttempts()).isZero();
        verify(userRepository).save(user);
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
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                PASSWORD_HASH);
        user.verifyEmail();
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
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                PASSWORD_HASH);
        user.verifyEmail();
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
