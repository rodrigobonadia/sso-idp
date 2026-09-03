package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.MfaNotEnabledException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.TotpCodeVerifier;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpSecretEncryptor;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
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
class VerifyMfaTotpChallengeUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();

    @Mock
    private MfaChallengeRepository mfaChallengeRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    @Mock
    private TotpSecretEncryptor totpSecretEncryptor;

    @Mock
    private TotpCodeVerifier totpCodeVerifier;

    @Mock
    private UserRepository userRepository;

    private VerifyMfaTotpChallengeUseCase useCase;
    private User user;
    private TokenHash tokenHash;
    private byte[] rawSecretBytes;
    private EncryptedTotpSecret encryptedSecret;

    @BeforeEach
    void setUp() {
        useCase = new VerifyMfaTotpChallengeUseCase(
                mfaChallengeRepository,
                verificationTokenHasher,
                totpCredentialRepository,
                totpSecretEncryptor,
                totpCodeVerifier,
                userRepository);
        user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
        tokenHash = TokenHash.of("some-hash-value");
        rawSecretBytes = "raw-secret-bytes".getBytes();
        encryptedSecret = EncryptedTotpSecret.of("Y2lwaGVydGV4dA==");
    }

    @Test
    void completesLoginForACorrectCodeAndConsumesTheChallenge() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge =
                MfaChallenge.issue(user.id(), TENANT_ID, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        TotpCredential active = TotpCredential.enroll(user.id(), encryptedSecret, Instant.now());
        active.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(active));
        when(totpSecretEncryptor.decrypt(encryptedSecret)).thenReturn(rawSecretBytes);
        when(totpCodeVerifier.verify(eq(rawSecretBytes), any())).thenReturn(true);
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        LoginResult result = useCase.execute(
                new VerifyMfaTotpChallengeCommand(RawVerificationToken.generate().value(), "123456"));

        assertThat(result.userId()).isEqualTo(user.id().value());
        assertThat(result.tenantId()).isEqualTo(TENANT_ID.value());
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(challenge.isConsumed()).isTrue();
        verify(mfaChallengeRepository).save(challenge);
    }

    @Test
    void rejectsAWrongCodeAndDoesNotConsumeTheChallengeSoItCanBeRetried() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge =
                MfaChallenge.issue(user.id(), TENANT_ID, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        TotpCredential active = TotpCredential.enroll(user.id(), encryptedSecret, Instant.now());
        active.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(active));
        when(totpSecretEncryptor.decrypt(encryptedSecret)).thenReturn(rawSecretBytes);
        when(totpCodeVerifier.verify(eq(rawSecretBytes), any())).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaTotpChallengeCommand(RawVerificationToken.generate().value(), "000000")))
                .isInstanceOf(InvalidMfaCodeException.class);

        assertThat(challenge.isConsumed()).isFalse();
        verify(mfaChallengeRepository, never()).save(any());
    }

    @Test
    void rejectsAnUnknownChallengeToken() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaTotpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(VerificationTokenNotFoundException.class);
    }

    @Test
    void rejectsAnAlreadyConsumedChallenge() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge =
                MfaChallenge.issue(user.id(), TENANT_ID, tokenHash, Instant.now(), Duration.ofMinutes(5));
        challenge.consume(Instant.now());
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaTotpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);
    }

    @Test
    void rejectsAnExpiredChallenge() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge = MfaChallenge.issue(
                user.id(), TENANT_ID, tokenHash, Instant.now().minusSeconds(600), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaTotpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void surfacesMfaNotEnabledWhenTheCredentialIsNoLongerActive() {
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);
        MfaChallenge challenge =
                MfaChallenge.issue(user.id(), TENANT_ID, tokenHash, Instant.now(), Duration.ofMinutes(5));
        when(mfaChallengeRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(challenge));
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(
                        new VerifyMfaTotpChallengeCommand(RawVerificationToken.generate().value(), "123456")))
                .isInstanceOf(MfaNotEnabledException.class);
    }
}
