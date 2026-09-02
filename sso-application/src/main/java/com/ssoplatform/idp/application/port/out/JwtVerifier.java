package com.ssoplatform.idp.application.port.out;

import java.util.Map;
import java.util.Optional;

/**
 * Output port that hides the concrete JWT parsing and signature-verification mechanics from the
 * application layer - the mirror image of {@link JwtSigner}. Implemented in {@code
 * sso-infrastructure} via a hand-rolled {@code RsaJwtVerifierAdapter} ({@code
 * java.security.Signature} with {@code SHA256withRSA} - RS256, the only algorithm this platform's
 * tokens are ever signed with), against the RFC 7515 JWS Compact Serialization string a {@link
 * JwtSigner} implementation produced.
 *
 * <p>Takes every candidate public key the caller considers acceptable, keyed by {@code kid}, rather
 * than a single key: a bearer token may have been signed under a tenant's now-{@code RETIRED}
 * signing key (see {@code SigningKeyRepository#findAllByTenantId}), which must still verify
 * successfully for as long as the token itself remains unexpired, even though it is no longer the
 * tenant's current key.
 *
 * <p>Returns an empty {@link Optional} for ANY failure - malformed compact serialization, a
 * header {@code alg} other than RS256, a {@code kid} absent from {@code publicKeysByKeyId}, a
 * signature that does not verify, or an {@code exp} claim in the past - deliberately without
 * distinguishing which. Callers (see {@code GetUserInfoUseCase}) report every one of these
 * identically as RFC 6750's {@code invalid_token}, exactly like {@code TokenUseCase}'s {@code
 * invalid_grant} enumeration-safety approach: a caller presenting a bearer token learns nothing
 * more than "this token is not acceptable".
 */
public interface JwtVerifier {

    Optional<Map<String, Object>> verify(String jwt, Map<String, byte[]> publicKeysByKeyId);
}
