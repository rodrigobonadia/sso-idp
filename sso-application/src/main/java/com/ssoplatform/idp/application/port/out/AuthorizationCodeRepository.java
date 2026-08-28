package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Optional;

/**
 * Output port for {@link AuthorizationCode} persistence. Looked up by {@link TokenHash}, mirroring
 * {@code PasswordResetTokenRepository}/{@code VerificationTokenRepository}: the only thing a
 * caller ever has in hand is the raw code value from an incoming request, hashed before this port
 * is consulted.
 *
 * <p>{@code findByCodeHash} is used by both {@code AuthorizeUseCase} (indirectly, only through
 * {@code save} in this sub-phase) and the not-yet-built Phase 3.4 {@code /token} endpoint, which is
 * the actual reader/consumer of a persisted code.
 */
public interface AuthorizationCodeRepository {

    AuthorizationCode save(AuthorizationCode authorizationCode);

    Optional<AuthorizationCode> findByCodeHash(TokenHash codeHash);
}
