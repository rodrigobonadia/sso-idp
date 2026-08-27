package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.verification.EmailVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Optional;

/**
 * Output port for {@link EmailVerificationToken} persistence. Looked up by its {@link TokenHash}
 * rather than by id, since the only thing callers ever have in hand is the raw token value from
 * an incoming request - which gets hashed before this port is even consulted.
 */
public interface VerificationTokenRepository {

    EmailVerificationToken save(EmailVerificationToken token);

    Optional<EmailVerificationToken> findByTokenHash(TokenHash tokenHash);
}
