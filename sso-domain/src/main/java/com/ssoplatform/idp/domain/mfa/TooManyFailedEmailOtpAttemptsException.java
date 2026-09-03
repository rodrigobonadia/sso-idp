package com.ssoplatform.idp.domain.mfa;

/**
 * Thrown when verifying (or recording another failed attempt against) an {@link EmailOtpCode}
 * that has already reached {@link EmailOtpCode#MAX_FAILED_ATTEMPTS} wrong tries. Unlike a TOTP
 * code (which naturally rotates every 30 seconds, making online brute-forcing impractical without
 * any explicit limit), an e-mailed code is static for its entire validity window - see {@link
 * EmailOtpCode}'s Javadoc for the full reasoning. Once this is thrown, the code is permanently
 * dead even if not yet time-expired; the caller must request a fresh one (re-submitting the same
 * enable/login action - see {@code phase_4_2_email_otp_mfa.md}).
 */
public class TooManyFailedEmailOtpAttemptsException extends RuntimeException {

    public TooManyFailedEmailOtpAttemptsException() {
        super("Too many incorrect attempts - request a new code");
    }
}
