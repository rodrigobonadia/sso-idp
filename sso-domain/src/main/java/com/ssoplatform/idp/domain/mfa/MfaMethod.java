package com.ssoplatform.idp.domain.mfa;

/**
 * Which second factor an {@link MfaChallenge} must be satisfied with. Recorded directly on the
 * challenge at issuance time (see {@code LoginUseCase#issueMfaChallenge}) rather than re-derived
 * at verification time by re-checking which credential is active - the challenge is meant to be a
 * self-contained record of exactly what login step 2 requires, and the active method genuinely
 * cannot change mid-challenge anyway (disabling MFA requires a session, which is exactly what does
 * not exist yet while a challenge is outstanding).
 */
public enum MfaMethod {
    TOTP,
    EMAIL_OTP
}
