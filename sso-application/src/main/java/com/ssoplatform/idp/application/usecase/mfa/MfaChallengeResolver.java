package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Instant;
import java.util.Objects;

/**
 * Shared "resolve a live MFA challenge, and consume it once the second factor actually checks
 * out" behavior for {@link VerifyMfaTotpChallengeUseCase} and {@link
 * VerifyMfaRecoveryCodeChallengeUseCase} - genuinely identical business behavior between the two
 * (not merely similar-looking code), so a small shared package-private helper is justified rather
 * than duplicating it.
 *
 * <p>Deliberately split into {@link #resolve} and {@link #consume} rather than one atomic
 * operation: unlike a password-reset token (single-use for a single action), a wrong code must
 * NOT burn the challenge - the same shape as re-entering a password wrong doesn't burn the login
 * attempt outright. A user who mistypes their TOTP code gets to retry against the same challenge
 * until it naturally expires (5 minutes); the challenge is only actually consumed once a real
 * factor check has succeeded, by the caller invoking {@link #consume}.
 */
final class MfaChallengeResolver {

    private final MfaChallengeRepository mfaChallengeRepository;
    private final VerificationTokenHasher verificationTokenHasher;

    MfaChallengeResolver(MfaChallengeRepository mfaChallengeRepository, VerificationTokenHasher verificationTokenHasher) {
        this.mfaChallengeRepository =
                Objects.requireNonNull(mfaChallengeRepository, "mfaChallengeRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
    }

    /** Looks up a still-live (not consumed, not expired) challenge by its raw token, without
     * consuming it. */
    MfaChallenge resolve(String rawChallengeToken) {
        RawVerificationToken rawToken = RawVerificationToken.of(rawChallengeToken);
        TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
        MfaChallenge challenge =
                mfaChallengeRepository.findByTokenHash(tokenHash).orElseThrow(VerificationTokenNotFoundException::new);
        if (challenge.isConsumed()) {
            throw new VerificationTokenAlreadyConsumedException();
        }
        if (challenge.isExpired(Instant.now())) {
            throw new VerificationTokenExpiredException();
        }
        return challenge;
    }

    /** Marks a challenge as consumed after its second factor has been verified. */
    void consume(MfaChallenge challenge) {
        challenge.consume(Instant.now());
        mfaChallengeRepository.save(challenge);
    }
}
