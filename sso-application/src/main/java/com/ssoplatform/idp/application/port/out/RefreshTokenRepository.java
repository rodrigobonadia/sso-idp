package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenFamilyId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.List;
import java.util.Optional;

/**
 * Output port for {@link RefreshToken} persistence. Looked up by {@link TokenHash}, mirroring
 * {@link AuthorizationCodeRepository}: the only thing a caller ever has in hand is the raw
 * {@code refresh_token} value from an incoming request, hashed before this port is consulted.
 *
 * <p>{@code findAllByFamilyId} exists for exactly one reason: reuse detection. When {@code
 * TokenUseCase} discovers that a presented refresh token has already been rotated or revoked (see
 * {@code RefreshToken.rotate}), it must revoke every token that shares that family - not just the
 * one presented - and this method is what lets it fetch the whole chain in one call to do so.
 */
public interface RefreshTokenRepository {

    RefreshToken save(RefreshToken refreshToken);

    Optional<RefreshToken> findByTokenHash(TokenHash tokenHash);

    List<RefreshToken> findAllByFamilyId(RefreshTokenFamilyId familyId);
}
