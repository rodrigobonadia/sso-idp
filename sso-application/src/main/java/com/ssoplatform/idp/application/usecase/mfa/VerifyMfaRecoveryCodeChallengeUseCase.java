package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.RecoveryCodeHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.RawRecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.user.User;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Completes the second step of a two-step login using one of the user's recovery codes instead of
 * a live TOTP code - the fallback path for when the authenticator device itself is lost. Mirrors
 * {@link VerifyMfaTotpChallengeUseCase} exactly except for how the factor is checked: since {@code
 * RecoveryCodeHash} values are salted (BCrypt), the candidate cannot be looked up by hash equality
 * - every one of the user's unconsumed codes is checked in turn via {@link
 * RecoveryCodeHasher#matches}.
 *
 * <p>The matched code is consumed (single-use) together with the challenge - a recovery code used
 * once can never be used again, exactly like every other single-use token in this system.
 */
public class VerifyMfaRecoveryCodeChallengeUseCase {

    private final MfaChallengeResolver challengeResolver;
    private final RecoveryCodeRepository recoveryCodeRepository;
    private final RecoveryCodeHasher recoveryCodeHasher;
    private final UserRepository userRepository;

    public VerifyMfaRecoveryCodeChallengeUseCase(
            MfaChallengeRepository mfaChallengeRepository,
            VerificationTokenHasher verificationTokenHasher,
            RecoveryCodeRepository recoveryCodeRepository,
            RecoveryCodeHasher recoveryCodeHasher,
            UserRepository userRepository) {
        this.challengeResolver = new MfaChallengeResolver(mfaChallengeRepository, verificationTokenHasher);
        this.recoveryCodeRepository =
                Objects.requireNonNull(recoveryCodeRepository, "recoveryCodeRepository must not be null");
        this.recoveryCodeHasher = Objects.requireNonNull(recoveryCodeHasher, "recoveryCodeHasher must not be null");
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
    }

    public LoginResult execute(VerifyMfaRecoveryCodeChallengeCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        MfaChallenge challenge = challengeResolver.resolve(command.challengeToken());

        RawRecoveryCode candidate = RawRecoveryCode.of(command.recoveryCode());
        List<RecoveryCode> unconsumedCodes = recoveryCodeRepository.findUnconsumedByUserId(challenge.userId());
        RecoveryCode matched = unconsumedCodes.stream()
                .filter(recoveryCode -> recoveryCodeHasher.matches(candidate, recoveryCode.codeHash()))
                .findFirst()
                .orElseThrow(InvalidMfaCodeException::new);

        matched.consume(Instant.now());
        recoveryCodeRepository.save(matched);
        challengeResolver.consume(challenge);

        User user = userRepository
                .findById(challenge.userId())
                .orElseThrow(() -> new UserNotFoundException(challenge.userId().value()));
        return new LoginResult(user.id().value(), challenge.tenantId().value(), user.email().value());
    }
}
