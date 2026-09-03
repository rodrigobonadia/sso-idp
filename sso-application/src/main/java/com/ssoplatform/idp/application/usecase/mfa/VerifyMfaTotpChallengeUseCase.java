package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.MfaNotEnabledException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.TotpCodeVerifier;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpSecretEncryptor;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.TotpCode;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.User;
import java.util.Objects;

/**
 * Completes the second step of a two-step login: given the challenge token from {@code
 * LoginOutcome.MfaChallengeIssued} and a code from the user's authenticator app, verifies it
 * against the user's active TOTP credential and - only then - returns the same {@link LoginResult}
 * {@code LoginUseCase} would have returned directly had MFA not been required. The caller (API
 * layer) establishes the session from this result exactly like it would for {@code
 * LoginOutcome.Authenticated}.
 *
 * <p>{@link MfaNotEnabledException} here is a defensive/should-never-happen guard: a challenge is
 * only ever issued because an active credential existed for that user at login time (see {@code
 * LoginUseCase}), and nothing on this path can remove it in between (disabling MFA requires a
 * password re-check {@code LoginUseCase} never performs).
 */
public class VerifyMfaTotpChallengeUseCase {

    private final MfaChallengeResolver challengeResolver;
    private final TotpCredentialRepository totpCredentialRepository;
    private final TotpSecretEncryptor totpSecretEncryptor;
    private final TotpCodeVerifier totpCodeVerifier;
    private final UserRepository userRepository;

    public VerifyMfaTotpChallengeUseCase(
            MfaChallengeRepository mfaChallengeRepository,
            VerificationTokenHasher verificationTokenHasher,
            TotpCredentialRepository totpCredentialRepository,
            TotpSecretEncryptor totpSecretEncryptor,
            TotpCodeVerifier totpCodeVerifier,
            UserRepository userRepository) {
        this.challengeResolver = new MfaChallengeResolver(mfaChallengeRepository, verificationTokenHasher);
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.totpSecretEncryptor =
                Objects.requireNonNull(totpSecretEncryptor, "totpSecretEncryptor must not be null");
        this.totpCodeVerifier = Objects.requireNonNull(totpCodeVerifier, "totpCodeVerifier must not be null");
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
    }

    public LoginResult execute(VerifyMfaTotpChallengeCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        MfaChallenge challenge = challengeResolver.resolve(command.challengeToken());

        // The code's shape is validated, and the credential is looked up and decrypted, BEFORE
        // the challenge is consumed - a submission that turns out to be wrong must never burn it.
        TotpCode code = TotpCode.of(command.code());
        TotpCredential credential = totpCredentialRepository
                .findByUserId(challenge.userId())
                .filter(TotpCredential::isActive)
                .orElseThrow(MfaNotEnabledException::new);
        byte[] rawSecret = totpSecretEncryptor.decrypt(credential.encryptedSecret());
        if (!totpCodeVerifier.verify(rawSecret, code)) {
            throw new InvalidMfaCodeException();
        }

        challengeResolver.consume(challenge);

        User user = userRepository
                .findById(challenge.userId())
                .orElseThrow(() -> new UserNotFoundException(challenge.userId().value()));
        return new LoginResult(user.id().value(), challenge.tenantId().value(), user.email().value());
    }
}
