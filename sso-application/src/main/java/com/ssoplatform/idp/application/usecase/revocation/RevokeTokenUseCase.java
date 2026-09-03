package com.ssoplatform.idp.application.usecase.revocation;

import com.ssoplatform.idp.application.exception.OAuthRevocationException;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.RefreshTokenRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.InvalidClientIdException;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.verification.InvalidVerificationTokenException;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Objects;

/**
 * Handles a {@code POST /revoke} request (RFC 7009): invalidates a refresh token the calling
 * client owns.
 *
 * <p>Only a {@link RefreshToken} can genuinely be revoked here - this platform's access tokens are
 * self-contained, unrevoked-until-expiry JWTs with no persisted row at all (see {@code
 * architecture_decisions.md}'s discussion of that trade-off, mitigated by their short TTL), so
 * presenting one to this endpoint is a documented no-op, not an error: RFC 7009 §2.1 explicitly
 * allows an authorization server that does not support revoking a particular token type to simply
 * respond with HTTP 200 anyway.
 *
 * <p>Revokes the token's ENTIRE rotation family (mirroring {@code
 * TokenUseCase#revokeEntireFamily}, reused here by the same duplicated-per-use-case shape, not a
 * shared helper - see that method's Javadoc for why a family, not just the one presented row, is
 * the right unit of revocation: it represents one continuous login, and a client asking to revoke
 * any token in it means "end this session").
 *
 * <p>Per RFC 7009 §2.2, EVERY outcome other than the request itself being malformed - an unknown
 * token, one already revoked, or one that belongs to a different client or tenant than the caller
 * authenticated as - is a silent success (this method simply returns, doing nothing): a caller
 * must never be able to use this endpoint's response to learn whether a given token value exists,
 * exactly the same enumeration-safety reasoning {@code IntrospectTokenUseCase} documents for
 * {@code {"active": false}}. {@link OAuthRevocationException} is reserved for failures that
 * prevent evaluating the request AT ALL - a missing {@code token} parameter, or the calling
 * client's own credentials being wrong.
 */
public class RevokeTokenUseCase {

    private final OAuthClientRepository oauthClientRepository;
    private final ClientSecretHasher clientSecretHasher;
    private final RefreshTokenRepository refreshTokenRepository;
    private final VerificationTokenHasher verificationTokenHasher;

    public RevokeTokenUseCase(
            OAuthClientRepository oauthClientRepository,
            ClientSecretHasher clientSecretHasher,
            RefreshTokenRepository refreshTokenRepository,
            VerificationTokenHasher verificationTokenHasher) {
        this.oauthClientRepository =
                Objects.requireNonNull(oauthClientRepository, "oauthClientRepository must not be null");
        this.clientSecretHasher = Objects.requireNonNull(clientSecretHasher, "clientSecretHasher must not be null");
        this.refreshTokenRepository =
                Objects.requireNonNull(refreshTokenRepository, "refreshTokenRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
    }

    public void execute(RevokeTokenCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());
        OAuthClient client = authenticateClient(command, tenantId);

        if (isBlank(command.token())) {
            throw new OAuthRevocationException("invalid_request", "token must not be blank");
        }

        TokenHash tokenHash;
        try {
            tokenHash = verificationTokenHasher.hash(RawVerificationToken.of(command.token()));
        } catch (InvalidVerificationTokenException ex) {
            // Not even shaped like a refresh token (e.g. an access token JWT) - nothing this
            // endpoint can revoke; see the class Javadoc.
            return;
        }

        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash).orElse(null);
        if (refreshToken == null
                || !refreshToken.tenantId().equals(tenantId)
                || !refreshToken.oauthClientId().equals(client.id())) {
            return;
        }

        for (RefreshToken member : refreshTokenRepository.findAllByFamilyId(refreshToken.familyId())) {
            member.revoke();
            refreshTokenRepository.save(member);
        }
    }

    /** Mirrors {@code TokenUseCase#authenticateClient}, minus the grant-type check - see {@code
     * IntrospectTokenUseCase#authenticateClient}, which this is otherwise identical to. */
    private OAuthClient authenticateClient(RevokeTokenCommand command, TenantId tenantId) {
        if (isBlank(command.basicAuthClientId()) || isBlank(command.basicAuthClientSecret())) {
            throw new OAuthRevocationException("invalid_client", "Client authentication is required");
        }

        ClientId clientId;
        try {
            clientId = ClientId.of(command.basicAuthClientId());
        } catch (InvalidClientIdException ex) {
            throw new OAuthRevocationException("invalid_client", "Client authentication failed");
        }

        OAuthClient client = oauthClientRepository
                .findByClientId(clientId)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(() -> new OAuthRevocationException("invalid_client", "Client authentication failed"));

        if (client.isPublic() || !clientSecretHasher.matches(command.basicAuthClientSecret(), client.clientSecretHash())) {
            throw new OAuthRevocationException("invalid_client", "Client authentication failed");
        }
        if (!client.isUsable()) {
            throw new OAuthRevocationException("invalid_client", "Client authentication failed");
        }

        return client;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
