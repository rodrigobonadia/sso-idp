package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Optional;

/**
 * Output port for {@link PasswordResetToken} persistence. Looked up by its {@link TokenHash}
 * rather than by id, since the only thing callers ever have in hand is the raw token value from
 * an incoming request - which gets hashed before this port is even consulted. Mirrors {@code
 * VerificationTokenRepository} exactly; kept as a separate port (and a separate persisted table)
 * because a password-reset token and an e-mail-verification token are looked up independently and
 * must never be confused with one another.
 */
public interface PasswordResetTokenRepository {

    PasswordResetToken save(PasswordResetToken token);

    Optional<PasswordResetToken> findByTokenHash(TokenHash tokenHash);
}
