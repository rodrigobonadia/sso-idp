package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;
import com.ssoplatform.idp.domain.user.User;
import java.time.Instant;
import java.util.Objects;

/**
 * Completes the second step of a two-step login using an e-mailed OTP code, mirroring {@link
 * VerifyMfaTotpChallengeUseCase} exactly except for how the factor is checked: the code was
 * generated and e-mailed by {@code LoginUseCase} at challenge-issuance time (not derived on demand
 * from a shared secret like TOTP), so it is looked up by the challenge's own id rather than
 * recomputed - exactly one {@link EmailOtpCode} is ever issued per {@link MfaChallenge}.
 *
 * <p>A wrong code does NOT burn the {@code MfaChallenge} itself (a genuine retry against the same
 * challenge still works, same policy as TOTP) - but it DOES count against {@link
 * EmailOtpCode#MAX_FAILED_ATTEMPTS}, since (unlike a TOTP code) this one stays valid and unchanged
 * for the challenge's whole 5-minute window - see {@link EmailOtpCode}'s Javadoc for why that
 * distinction matters.
 */
public class VerifyMfaEmailOtpChallengeUseCase {

    private final MfaChallengeResolver challengeResolver;
    private final EmailOtpCodeRepository emailOtpCodeRepository;
    private final EmailOtpCodeHasher emailOtpCodeHasher;
    private final UserRepository userRepository;

    public VerifyMfaEmailOtpChallengeUseCase(
            MfaChallengeRepository mfaChallengeRepository,
            VerificationTokenHasher verificationTokenHasher,
            EmailOtpCodeRepository emailOtpCodeRepository,
            EmailOtpCodeHasher emailOtpCodeHasher,
            UserRepository userRepository) {
        this.challengeResolver = new MfaChallengeResolver(mfaChallengeRepository, verificationTokenHasher);
        this.emailOtpCodeRepository =
                Objects.requireNonNull(emailOtpCodeRepository, "emailOtpCodeRepository must not be null");
        this.emailOtpCodeHasher = Objects.requireNonNull(emailOtpCodeHasher, "emailOtpCodeHasher must not be null");
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
    }

    public LoginResult execute(VerifyMfaEmailOtpChallengeCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        MfaChallenge challenge = challengeResolver.resolve(command.challengeToken());

        EmailOtpCode code = emailOtpCodeRepository
                .findByMfaChallengeId(challenge.id())
                .orElseThrow(() -> new IllegalStateException(
                        "EmailOtpCode must exist for an issued email-otp MfaChallenge"));

        RawEmailOtpCode candidate = RawEmailOtpCode.of(command.code());
        Instant now = Instant.now();
        if (!emailOtpCodeHasher.matches(candidate, code.codeHash())) {
            code.recordFailedAttempt(now);
            emailOtpCodeRepository.save(code);
            throw new InvalidMfaCodeException();
        }
        code.consume(now);
        emailOtpCodeRepository.save(code);

        challengeResolver.consume(challenge);

        User user = userRepository
                .findById(challenge.userId())
                .orElseThrow(() -> new UserNotFoundException(challenge.userId().value()));
        return new LoginResult(user.id().value(), challenge.tenantId().value(), user.email().value());
    }
}
