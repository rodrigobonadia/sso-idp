package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.RecoveryCodeHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.RawRecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class VerifyMfaRecoveryCodeChallengeUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();

    @Mock
    private MfaChallengeRepository mfaChallengeRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    @Mock
    private RecoveryCodeHasher recoveryCodeHasher;

    @Mock
    private UserRepository userRepository;

    private VerifyMfaRecoveryCodeChallengeUseCase useCase;
    private User user;
    private TokenHash tokenHash;
    private MfaChallenge challenge;

    @BeforeEach
    void setUp() {
        useCase = new VerifyMfaRecoveryCodeChallengeUseCase(
                mfaChallengeRepository, verificationTokenHasher, recoveryCodeRepository, recoveryCodeHasher, userRepository);
        user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
        tokenHash = TokenHash.of("some-hash-value");
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        challenge = MfaChallenge.issue(user.id(), TENANT_ID, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
    }

    @Test
    void completesLoginWithTheMatchingUnconsumedCodeAndConsumesBothItAndTheChallenge() {
        RecoveryCode matching = RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$matchinghash"), Instant.now());
        RecoveryCode other = RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$otherhash"), Instant.now());
        when(recoveryCodeRepository.findUnconsumedByUserId(user.id())).thenReturn(List.of(other, matching));
        when(recoveryCodeHasher.matches(any(), eq(other.codeHash()))).thenReturn(false);
        when(recoveryCodeHasher.matches(any(), eq(matching.codeHash()))).thenReturn(true);
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        LoginResult result = useCase.execute(new VerifyMfaRecoveryCodeChallengeCommand(
                RawVerificationToken.generate().value(), RawRecoveryCode.generate().value()));

        assertThat(result.userId()).isEqualTo(user.id().value());
        assertThat(result.tenantId()).isEqualTo(TENANT_ID.value());
        assertThat(matching.isConsumed()).isTrue();
        assertThat(other.isConsumed()).isFalse();
        assertThat(challenge.isConsumed()).isTrue();
        verify(recoveryCodeRepository).save(matching);
    }

    @Test
    void rejectsACodeThatMatchesNoUnconsumedCodeAndDoesNotConsumeTheChallenge() {
        RecoveryCode other = RecoveryCode.issue(user.id(), RecoveryCodeHash.of("$2a$12$otherhash"), Instant.now());
        when(recoveryCodeRepository.findUnconsumedByUserId(user.id())).thenReturn(List.of(other));
        when(recoveryCodeHasher.matches(any(), eq(other.codeHash()))).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(new VerifyMfaRecoveryCodeChallengeCommand(
                        RawVerificationToken.generate().value(), RawRecoveryCode.generate().value())))
                .isInstanceOf(InvalidMfaCodeException.class);

        assertThat(other.isConsumed()).isFalse();
        assertThat(challenge.isConsumed()).isFalse();
        verify(recoveryCodeRepository, never()).save(any());
        verify(mfaChallengeRepository, never()).save(any());
    }

    @Test
    void rejectsAnAlreadyConsumedRecoveryCodeEvenIfItWouldOtherwiseMatch() {
        // findUnconsumedByUserId is the repository's job to filter - this test documents that the
        // use case relies on it rather than re-checking isConsumed() itself, since a consumed code
        // is never even offered as a candidate.
        when(recoveryCodeRepository.findUnconsumedByUserId(user.id())).thenReturn(List.of());

        assertThatThrownBy(() -> useCase.execute(new VerifyMfaRecoveryCodeChallengeCommand(
                        RawVerificationToken.generate().value(), RawRecoveryCode.generate().value())))
                .isInstanceOf(InvalidMfaCodeException.class);
    }
}
