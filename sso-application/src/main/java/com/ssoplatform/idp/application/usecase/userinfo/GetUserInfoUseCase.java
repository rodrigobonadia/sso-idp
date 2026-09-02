package com.ssoplatform.idp.application.usecase.userinfo;

import com.ssoplatform.idp.application.exception.InvalidBearerTokenException;
import com.ssoplatform.idp.application.port.out.JwtVerifier;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.user.UserStatus;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Handles a {@code GET /userinfo} request (OpenID Connect Core 1.0 §5.3): validates the presented
 * bearer access token and returns whichever claims its {@code scope} grants.
 *
 * <p>Every failure - a missing/blank token, a token that fails {@link JwtVerifier} verification
 * for any reason (unknown {@code kid}, bad signature, expired), a {@code sub} that is not a
 * well-formed user id, a {@code sub} that no longer resolves to a real user of THIS tenant, or a
 * token whose {@code scope} lacks {@code openid} - is reported identically via {@link
 * InvalidBearerTokenException}, never distinguishing which check failed: exactly the same
 * enumeration-safety reasoning {@code TokenUseCase} documents for {@code invalid_grant} applies
 * here to RFC 6750's {@code invalid_token}/{@code insufficient_scope}.
 *
 * <p>Candidate verification keys are every {@link SigningKey} the tenant has ever had - including
 * {@code RETIRED} ones (see {@link SigningKeyRepository#findAllByTenantId}) - since an access
 * token issued just before a key rotation must keep verifying for the rest of its short (15
 * minute) lifetime.
 */
public class GetUserInfoUseCase {

    private static final String OPENID_SCOPE = "openid";
    private static final String EMAIL_SCOPE = "email";
    private static final String PROFILE_SCOPE = "profile";

    private final SigningKeyRepository signingKeyRepository;
    private final JwtVerifier jwtVerifier;
    private final UserRepository userRepository;

    public GetUserInfoUseCase(
            SigningKeyRepository signingKeyRepository, JwtVerifier jwtVerifier, UserRepository userRepository) {
        this.signingKeyRepository =
                Objects.requireNonNull(signingKeyRepository, "signingKeyRepository must not be null");
        this.jwtVerifier = Objects.requireNonNull(jwtVerifier, "jwtVerifier must not be null");
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
    }

    public UserInfoResult execute(GetUserInfoCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        if (isBlank(command.bearerToken())) {
            throw new InvalidBearerTokenException("invalid_request", "A bearer access token is required");
        }

        TenantId tenantId = TenantId.of(command.tenantId());
        Map<String, byte[]> publicKeysByKeyId = candidateKeys(tenantId);

        Map<String, Object> claims = jwtVerifier
                .verify(command.bearerToken(), publicKeysByKeyId)
                .orElseThrow(() -> new InvalidBearerTokenException(
                        "invalid_token", "The access token is invalid or has expired"));

        Set<String> scopes = parseScopes(claims.get("scope"));
        if (!scopes.contains(OPENID_SCOPE)) {
            throw new InvalidBearerTokenException(
                    "insufficient_scope", "The access token was not issued with the openid scope");
        }

        User user = resolveUser(claims.get("sub"), tenantId);

        String email = null;
        Boolean emailVerified = null;
        if (scopes.contains(EMAIL_SCOPE)) {
            email = user.email().value();
            emailVerified = user.status() != UserStatus.PENDING_VERIFICATION;
        }

        String givenName = null;
        String familyName = null;
        String name = null;
        if (scopes.contains(PROFILE_SCOPE)) {
            givenName = user.givenName().value();
            familyName = user.familyName().value();
            name = givenName + " " + familyName;
        }

        return new UserInfoResult(user.id().value().toString(), email, emailVerified, givenName, familyName, name);
    }

    private Map<String, byte[]> candidateKeys(TenantId tenantId) {
        Map<String, byte[]> keys = new HashMap<>();
        for (SigningKey signingKey : signingKeyRepository.findAllByTenantId(tenantId)) {
            keys.put(signingKey.kid().value(), Base64.getDecoder().decode(signingKey.publicKey().value()));
        }
        return keys;
    }

    private User resolveUser(Object subClaim, TenantId tenantId) {
        if (!(subClaim instanceof String sub)) {
            throw new InvalidBearerTokenException("invalid_token", "The access token is invalid or has expired");
        }
        UserId userId;
        try {
            userId = UserId.of(sub);
        } catch (IllegalArgumentException ex) {
            throw new InvalidBearerTokenException("invalid_token", "The access token is invalid or has expired");
        }
        return userRepository
                .findById(userId)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(() -> new InvalidBearerTokenException(
                        "invalid_token", "The access token is invalid or has expired"));
    }

    private static Set<String> parseScopes(Object scopeClaim) {
        if (!(scopeClaim instanceof String scopeString) || scopeString.isBlank()) {
            return Set.of();
        }
        return Set.of(scopeString.split(" "));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
