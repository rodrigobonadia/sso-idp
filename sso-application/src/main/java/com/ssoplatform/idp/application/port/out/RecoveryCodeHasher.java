package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.RawRecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;

/**
 * Output port that hides the concrete hashing scheme for MFA recovery codes from the application
 * layer. Implemented in {@code sso-infrastructure} via {@code BCryptRecoveryCodeHasherAdapter}.
 *
 * <p>Deliberately BCrypt (like {@link PasswordHasher}), not the fast unsalted SHA-256 {@link
 * VerificationTokenHasher} uses: a recovery code carries only ~50 bits of entropy (see {@code
 * RawRecoveryCode}), not 256 - low enough that a slow, salted algorithm is the right protection
 * for a stolen hash, the same reasoning that justifies BCrypt for user passwords. Because BCrypt
 * hashes are salted, {@link #matches} - not a hash-equality lookup - is the only way to check a
 * candidate against a stored hash.
 */
public interface RecoveryCodeHasher {

    RecoveryCodeHash hash(RawRecoveryCode rawCode);

    boolean matches(RawRecoveryCode candidate, RecoveryCodeHash hash);
}
