package com.ssoplatform.idp.application.port.out;

import java.util.Map;

/**
 * Output port that hides the concrete JWT construction and signing mechanics from the application
 * layer. Implemented in {@code sso-infrastructure} via a hand-rolled {@code RsaJwtSignerAdapter}
 * (RFC 7515 JWS Compact Serialization, {@code java.security.Signature} with {@code
 * SHA256withRSA} - RS256, the platform's only supported algorithm, see {@code
 * SigningKey#ALGORITHM}) - no JWT library is used, by explicit project decision.
 *
 * <p>Deliberately takes a plain {@code Map<String, Object>} of claims rather than a typed "Claims"
 * value object: {@code TokenUseCase} builds different claim sets for an access token (RFC 9068
 * shape) versus an OIDC ID token (OpenID Connect Core 1.0 §2 shape), and this port has no opinion
 * about which - it only knows how to encode, sign, and compact-serialize whatever map it is given.
 * This also keeps {@code sso-application} free of any JSON-library dependency: only the {@code
 * sso-infrastructure} adapter needs Jackson to serialize the header/payload, exactly like {@code
 * PrivateKeyEncryptor} keeps AES/Cipher details out of this layer.
 *
 * <p>{@code privateKeyDer} is the already-decrypted PKCS8 DER bytes of the signing tenant's current
 * RSA private key (see {@code PrivateKeyEncryptor#decrypt}) - this port never touches encrypted key
 * material or persistence itself. {@code keyId} becomes the {@code kid} header claim, letting a
 * verifier pick the matching public key from the tenant's JWKS document (see {@code
 * JwksController}).
 */
public interface JwtSigner {

    String sign(Map<String, Object> claims, byte[] privateKeyDer, String keyId);
}
