package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Optional;

/** Output port for {@link MfaChallenge} persistence, looked up by the hash of the raw token
 * presented back on the login flow's second step - mirrors {@code PasswordResetTokenRepository}. */
public interface MfaChallengeRepository {

    MfaChallenge save(MfaChallenge challenge);

    Optional<MfaChallenge> findByTokenHash(TokenHash tokenHash);
}
