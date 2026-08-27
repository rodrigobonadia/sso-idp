package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;

/**
 * Output port that hides the concrete hashing scheme for verification tokens from the
 * application layer. Implemented in {@code sso-infrastructure}.
 *
 * <p>Deliberately a single {@code hash} method, unlike {@link PasswordHasher}'s {@code hash} +
 * {@code matches} pair: a verification token is a 256-bit random value, not a low-entropy
 * user-chosen secret, so its hash needs no per-value salt and can safely be looked up by exact
 * equality - there's no need for a constant-effort "matches" comparison against every candidate.
 */
public interface VerificationTokenHasher {

    TokenHash hash(RawVerificationToken rawToken);
}
