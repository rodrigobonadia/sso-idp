package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.oauth.ClientSecretHash;

/**
 * Output port that hides the concrete hashing scheme for OAuth client secrets from the
 * application layer. Implemented in {@code sso-infrastructure}.
 *
 * <p>Shaped like {@link PasswordHasher} (a {@code hash} + {@code matches} pair), not like {@link
 * VerificationTokenHasher} (hash-only): a client secret is looked up by {@code client_id} first
 * (via {@link OAuthClientRepository#findByClientId}), then the presented candidate secret must be
 * checked against that specific client's stored hash - the same "look up some other way, then
 * compare" shape a login password has, not the "look up by hash directly" shape a verification
 * token has.
 *
 * <p>Unlike {@link PasswordHasher}, however, the concrete implementation is expected to use a
 * fast hash (e.g. SHA-256) rather than a slow, salted one (BCrypt): a client secret - like a
 * verification/reset token - is generated as a high-entropy random value at provisioning time,
 * never chosen by a human, so it cannot be brute-forced from its hash regardless of hash speed.
 * See {@code Sha256VerificationTokenHasherAdapter}'s Javadoc for the identical reasoning.
 */
public interface ClientSecretHasher {

    ClientSecretHash hash(String rawSecret);

    boolean matches(String rawSecret, ClientSecretHash hash);
}
