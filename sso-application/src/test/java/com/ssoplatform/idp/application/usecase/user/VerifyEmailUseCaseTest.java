package com.ssoplatform.idp.application.usecase.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.port.out.VerificationTokenRepository;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.EmailVerificationToken;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VerifyEmailUseCaseTest {

    @Mock
    private VerificationTokenRepository verificationTokenRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private UserRepository userRepository;

    private VerifyEmailUseCase useCase;
    private TokenHash tokenHash;
    private User pendingUser;

    @BeforeEach
    void setUp() {
        useCase = new VerifyEmailUseCase(verificationTokenRepository, verificationTokenHasher, userRepository);
        tokenHash = TokenHash.of("some-hash-value");
        pendingUser = User.register(
                TenantId.generate(),
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
    }

    @Test
    void consumesTheTokenAndActivatesTheUserWhenTheTokenIsValid() {
        EmailVerificationToken token = EmailVerificationToken.issue(
                pendingUser.id(), tokenHash, Instant.now().minus(1, ChronoUnit.HOURS), java.time.Duration.ofHours(24));
        when(verificationTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(userRepository.findById(pendingUser.id())).thenReturn(Optional.of(pendingUser));
        when(userRepository.save(pendingUser)).thenReturn(pendingUser);

        VerifyEmailResult result = useCase.execute(new VerifyEmailCommand(RawVerificationToken.generate().value()));

        assertThat(result.userId()).isEqualTo(pendingUser.id().value());
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(token.isConsumed()).isTrue();
        assertThat(pendingUser.canAuthenticate()).isTrue();
        verify(verificationTokenRepository).save(token);
        verify(userRepository).save(pendingUser);
    }

    @Test
    void rejectsATokenThatDoesNotMatchAnyStoredHash() {
        when(verificationTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new VerifyEmailCommand(RawVerificationToken.generate().value())))
                .isInstanceOf(VerificationTokenNotFoundException.class);

        verify(userRepository, never()).findById(any());
    }

    @Test
    void rejectsATokenThatWasAlreadyConsumedAndDoesNotTouchTheUser() {
        EmailVerificationToken token = EmailVerificationToken.issue(
                pendingUser.id(), tokenHash, Instant.now().minus(1, ChronoUnit.HOURS), java.time.Duration.ofHours(24));
        token.consume(Instant.now());
        when(verificationTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> useCase.execute(new VerifyEmailCommand(RawVerificationToken.generate().value())))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);

        verify(userRepository, never()).findById(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    void surfacesADefensiveUserNotFoundExceptionWhenTheTokenPointsToNoUser() {
        EmailVerificationToken token = EmailVerificationToken.issue(
                UserId.generate(), tokenHash, Instant.now().minus(1, ChronoUnit.HOURS), java.time.Duration.ofHours(24));
        when(verificationTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(userRepository.findById(token.userId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new VerifyEmailCommand(RawVerificationToken.generate().value())))
                .isInstanceOf(UserNotFoundException.class);
    }
}
