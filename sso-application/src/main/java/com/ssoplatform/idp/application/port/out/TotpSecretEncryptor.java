package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;

/**
 * Output port that hides the concrete at-rest encryption scheme for TOTP secrets from the
 * application layer. Implemented in {@code sso-infrastructure} via {@code
 * AesGcmTotpSecretEncryptorAdapter} (AES-256-GCM, keyed from its own environment variable).
 *
 * <p>Deliberately a separate port from {@link PrivateKeyEncryptor} rather than a shared/generalized
 * "secret encryptor" - see {@code phase_4_1_totp_mfa.md} decision record: key separation between
 * signing-key material and TOTP secrets is a real defense-in-depth property (a leak of one
 * encryption secret does not expose the other class of data), and this mirrors the codebase's
 * existing convention of independent, purpose-specific implementations per aggregate.
 *
 * <p>Unlike {@code PrivateKeyEncryptor}, {@link #decrypt} here is exercised from day one: every
 * time a code needs verifying, the plaintext secret must be recovered to compute the expected
 * TOTP value.
 */
public interface TotpSecretEncryptor {

    EncryptedTotpSecret encrypt(byte[] rawSecret);

    byte[] decrypt(EncryptedTotpSecret encrypted);
}
