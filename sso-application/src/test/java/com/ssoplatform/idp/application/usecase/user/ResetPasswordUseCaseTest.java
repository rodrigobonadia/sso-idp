package com.ssoplatform.idp.application.usecase.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.PasswordResetTokenRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.user.UserStateException;
import com.ssoplatform.idp.domain.user.WeakPasswordException;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ResetPasswordUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final HashedPassword OLD_PASSWORD_HASH = HashedPassword.of("$2a$10$oldhashvalue");
    private static final HashedPassword NEW_PASSWORD_HASH = HashedPassword.of("$2a$10$newhashvalue");

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordHasher passwordHasher;

    private ResetPasswordUseCase useCase;
    private TokenHash tokenHash;

    @BeforeEach
    void setUp() {
        useCase = new ResetPasswordUseCase(
                passwordResetTokenRepository, verificationTokenHasher, userRepository, passwordHasher);
        tokenHash = TokenHash.of("some-hash-value");
    }

    @Test
    void resetsThePasswordForAnActiveAccountAndConsumesTheToken() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                OLD_PASSWORD_HASH);
        user.verifyEmail();
        PasswordResetToken token = PasswordResetToken.issue(
                user.id(), tokenHash, Instant.now().minusSeconds(30), Duration.ofHours(1));
        when(passwordResetTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(passwordHasher.hash(any())).thenReturn(NEW_PASSWORD_HASH);
        when(userRepository.save(user)).thenReturn(user);

        ResetPasswordResult result = useCase.execute(
                new ResetPasswordCommand(RawVerificationToken.generate().value(), "N3wStr0ng!Passw0rd"));

        assertThat(result.userId()).isEqualTo(user.id().value());
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(user.passwordHash()).isEqualTo(NEW_PASSWORD_HASH);
        assertThat(token.isConsumed()).isTrue();
        verify(passwordResetTokenRepository).save(token);
        verify(userRepository).save(user);
    }

    @Test
    void unlocksALockedAccountAndResetsFailedAttemptsUponSuccessfulReset() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                OLD_PASSWORD_HASH);
        user.verifyEmail();
        user.recordFailedLogin();
        user.recordFailedLogin();
        user.lock();
        PasswordResetToken token = PasswordResetToken.issue(
                user.id(), tokenHash, Instant.now().minusSeconds(30), Duration.ofHours(1));
        when(passwordResetTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(passwordHasher.hash(any())).thenReturn(NEW_PASSWORD_HASH);
        when(userRepository.save(user)).thenReturn(user);

        useCase.execute(new ResetPasswordCommand(RawVerificationToken.generate().value(), "N3wStr0ng!Passw0rd"));

        assertThat(user.canAuthenticate()).isTrue();
        assertThat(user.failedLoginAttempts()).isZero();
    }

    @Test
    void rejectsResettingAPasswordForADisabledAccount() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        User user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                OLD_PASSWORD_HASH);
        user.verifyEmail();
        user.disable();
        PasswordResetToken token = PasswordResetToken.issue(
                user.id(), tokenHash, Instant.now().minusSeconds(30), Duration.ofHours(1));
        when(passwordResetTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(passwordHasher.hash(any())).thenReturn(NEW_PASSWORD_HASH);

        assertThatThrownBy(() -> useCase.execute(
                        new ResetPasswordCommand(RawVerificationToken.generate().value(), "N3wStr0ng!Passw0rd")))
                .isInstanceOf(UserStateException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsATokenThatDoesNotMatchAnyStoredHash() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        when(passwordResetTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(
                        new ResetPasswordCommand(RawVerificationToken.generate().value(), "N3wStr0ng!Passw0rd")))
                .isInstanceOf(VerificationTokenNotFoundException.class);

        verify(userRepository, never()).findById(any());
    }

    @Test
    void rejectsATokenThatWasAlreadyConsumedAndDoesNotTouchTheUser() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        PasswordResetToken token = PasswordResetToken.issue(
                UserId.generate(), tokenHash, Instant.now().minusSeconds(30), Duration.ofHours(1));
        token.consume(Instant.now());
        when(passwordResetTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> useCase.execute(
                        new ResetPasswordCommand(RawVerificationToken.generate().value(), "N3wStr0ng!Passw0rd")))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);

        verify(userRepository, never()).findById(any());
    }

    @Test
    void rejectsAWeakNewPasswordWithoutConsumingTheToken() {
        assertThatThrownBy(() ->
                        useCase.execute(new ResetPasswordCommand(RawVerificationToken.generate().value(), "weak")))
                .isInstanceOf(WeakPasswordException.class);

        verify(passwordResetTokenRepository, never()).findByTokenHash(any());
    }

    @Test
    void surfacesADefensiveUserNotFoundExceptionWhenTheTokenPointsToNoUser() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        PasswordResetToken token = PasswordResetToken.issue(
                UserId.generate(), tokenHash, Instant.now().minusSeconds(30), Duration.ofHours(1));
        when(passwordResetTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(userRepository.findById(token.userId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(
                        new ResetPasswordCommand(RawVerificationToken.generate().value(), "N3wStr0ng!Passw0rd")))
                .isInstanceOf(UserNotFoundException.class);
    }
}
