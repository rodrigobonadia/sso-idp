package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.TotpCode;

/**
 * Output port that hides the concrete TOTP (RFC 6238) code generation/verification algorithm from
 * the application layer. Implemented in {@code sso-infrastructure} via {@code
 * HmacSha1TotpCodeVerifierAdapter}, hand-rolled on top of the JDK's own {@code javax.crypto.Mac}
 * ({@code HmacSHA1}) - no external TOTP library is needed, consistent with this project's stated
 * goal of hand-implementing the protocols it demonstrates rather than delegating them.
 *
 * <p>{@code rawSecret} is always the already-decrypted secret bytes (see {@code
 * TotpSecretEncryptor#decrypt}) - this port never sees or manages encryption itself, only the
 * RFC 6238 time-step/HMAC computation and comparison.
 */
public interface TotpCodeVerifier {

    /** True if {@code candidate} matches the code {@code rawSecret} would produce at {@code
     * System.currentTimeMillis()}, allowing a small window on either side of the current 30-second
     * time step to tolerate reasonable clock drift between the server and the user's device. */
    boolean verify(byte[] rawSecret, TotpCode candidate);
}
