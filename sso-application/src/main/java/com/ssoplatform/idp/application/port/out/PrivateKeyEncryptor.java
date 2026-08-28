package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;

/**
 * Output port that hides the concrete at-rest encryption scheme for RSA private signing keys from
 * the application layer. Implemented in {@code sso-infrastructure} via {@code
 * AesGcmPrivateKeyEncryptorAdapter} (AES-256-GCM, keyed from an environment variable never stored
 * alongside the database - see {@code architecture_decisions.md}, decision (j)).
 *
 * <p>{@link #decrypt} is not yet called by any use case in this sub-phase (no use case signs a
 * token yet - that is Phase 3.3/3.4), but is included so this port's shape is complete and ready:
 * an encryption scheme with no matching decryption is not a real port.
 */
public interface PrivateKeyEncryptor {

    EncryptedPrivateKeyMaterial encrypt(byte[] privateKeyDer);

    byte[] decrypt(EncryptedPrivateKeyMaterial encrypted);
}
