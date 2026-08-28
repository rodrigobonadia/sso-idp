package com.ssoplatform.idp.application.port.out;

/**
 * Output port that hides the concrete key-generation parameters (algorithm, key size) from the
 * application layer. Implemented in {@code sso-infrastructure} via {@code
 * RsaSigningKeyPairGeneratorAdapter} - RSA, 4096 bits, per {@code architecture_decisions.md}.
 */
public interface SigningKeyPairGenerator {

    GeneratedKeyPair generate();
}
