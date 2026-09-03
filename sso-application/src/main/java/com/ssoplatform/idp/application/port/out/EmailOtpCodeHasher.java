package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;

/**
 * Output port that hides the concrete hashing scheme for e-mail OTP codes from the application
 * layer. Implemented in {@code sso-infrastructure} via {@code BCryptEmailOtpCodeHasherAdapter}.
 *
 * <p>Deliberately BCrypt (like {@link RecoveryCodeHasher}/{@link PasswordHasher}), not the fast
 * unsalted SHA-256 {@link VerificationTokenHasher} uses: a 6-digit e-mail OTP code carries only
 * ~20 bits of entropy - even lower than a recovery code's ~50 - so a slow, salted algorithm is the
 * right protection for a stolen hash. Because BCrypt hashes are salted, {@link #matches} - not a
 * hash-equality lookup - is the only way to check a candidate against a stored hash.
 */
public interface EmailOtpCodeHasher {

    EmailOtpCodeHash hash(RawEmailOtpCode rawCode);

    boolean matches(RawEmailOtpCode candidate, EmailOtpCodeHash hash);
}
