package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.MfaMethod;
import com.ssoplatform.idp.domain.mfa.TooManyFailedEmailOtpAttemptsException;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VerifyMfaEmailOtpChallengeUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();

    @Mock
    private MfaChallengeRepository mfaChallengeRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private EmailOtpCodeRepository emailOtpCodeRepository;

    @Mock
    private EmailOtpCodeHasher emailOtpCodeHasher;

    @Mock
    private UserRepository userRepository;

    private VerifyMfaEmailOtpChallengeUseCase useCase;
    private User user;
    private TokenHash tokenHash;
    private EmailOtpCodeHash codeHash;

    @BeforeEach
    void setUp() {
        useCase = new VerifyMfaEmailOtpChallengeUseCase(
                mfaChallengeRepository, verificationTokenHasher, emailOtpCodeRepository, emailOtpCodeHasher, userRepository);
        user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
        tokenHash = TokenHash.of("some-hash-value");
        codeHash = EmailOtpCodeHash.of("$2a$12$somehash");
    }

    @Test
    void completesLoginForACorrectCodeAndConsumesTheChallenge() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), TENANT_ID, MfaMethod.EMAIL_OTP, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        EmailOtpCode code = EmailOtpCode.issueForChallenge(
                user.id(), challenge.id(), codeHash, Instant.now(), Duration.ofMinutes(5));
        when(emailOtpCodeRepository.findByMfaChallengeId(challenge.id())).thenReturn(Optional.of(code));
        when(emailOtpCodeHasher.matches(any(), any())).thenReturn(true);
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        LoginResult result = useCase.execute(
                new VerifyMfaEmailOtpChallengeCommand(RawVerificationToken.generate().value(), "123456"));

        assertThat(result.userId()).isEqualTo(user.id().value());
        assertThat(result.tenantId()).isEqualTo(TENANT_ID.value());
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(code.isConsumed()).isTrue();
        assertThat(challenge.isConsumed()).isTrue();
        verify(emailOtpCodeRepository).save(code);
        verify(mfaChallengeRepository).save(challenge);
    }

    @Test
    void rejectsAWrongCodeRecordsTheFailedAttemptAndDoesNotConsumeTheChallengeSoItCanBeRetried() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), TENANT_ID, MfaMethod.EMAIL_OTP, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        EmailOtpCode code = EmailOtpCode.issueForChallenge(
                user.id(), challenge.id(), codeHash, Instant.now(), Duration.ofMinutes(5));
        when(emailOtpCodeRepository.findByMfaChallengeId(challenge.id())).thenReturn(Optional.of(code));
        when(emailOtpCodeHasher.matches(any(), any())).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaEmailOtpChallengeCommand(RawVerificationToken.generate().value(), "000000")))
                .isInstanceOf(InvalidMfaCodeException.class);

        assertThat(code.failedAttempts()).isEqualTo(1);
        assertThat(code.isConsumed()).isFalse();
        assertThat(challenge.isConsumed()).isFalse();
        verify(emailOtpCodeRepository).save(code);
        verify(mfaChallengeRepository, never()).save(any());
    }

    @Test
    void rejectsAnUnknownChallengeToken() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaEmailOtpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(VerificationTokenNotFoundException.class);
    }

    @Test
    void rejectsAnAlreadyConsumedChallenge() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), TENANT_ID, MfaMethod.EMAIL_OTP, tokenHash, Instant.now(), Duration.ofMinutes(5));
        challenge.consume(Instant.now());
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaEmailOtpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);
    }

    @Test
    void rejectsAnExpiredChallenge() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(),
                TENANT_ID,
                MfaMethod.EMAIL_OTP,
                tokenHash,
                Instant.now().minusSeconds(600),
                Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaEmailOtpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void rejectsACodeThatHasAlreadyExceededItsFailedAttemptLimit() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), TENANT_ID, MfaMethod.EMAIL_OTP, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        EmailOtpCode code = EmailOtpCode.issueForChallenge(
                user.id(), challenge.id(), codeHash, Instant.now(), Duration.ofMinutes(5));
        for (int i = 0; i < EmailOtpCode.MAX_FAILED_ATTEMPTS; i++) {
            code.recordFailedAttempt(Instant.now());
        }
        when(emailOtpCodeRepository.findByMfaChallengeId(challenge.id())).thenReturn(Optional.of(code));

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaEmailOtpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(TooManyFailedEmailOtpAttemptsException.class);

        verify(mfaChallengeRepository, never()).save(any());
    }

    @Test
    void throwsIllegalStateWhenNoEmailOtpCodeExistsForTheChallenge() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), TENANT_ID, MfaMethod.EMAIL_OTP, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        when(emailOtpCodeRepository.findByMfaChallengeId(challenge.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaEmailOtpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(IllegalStateException.class);
    }
}
