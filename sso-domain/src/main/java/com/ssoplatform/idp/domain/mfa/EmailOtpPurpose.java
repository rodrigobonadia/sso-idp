package com.ssoplatform.idp.domain.mfa;

/**
 * What a given {@link EmailOtpCode} is for - the two lifecycles that generate and verify an
 * e-mailed one-time code are otherwise identical in shape, but must never be confused with one
 * another: a code meant to confirm ENROLLING the method must never satisfy a LOGIN challenge, and
 * vice versa, even for the same user. {@link EmailOtpCode#mfaChallengeId()} is populated only for
 * {@link #LOGIN_CHALLENGE} codes (each tied to exactly one login attempt); {@link
 * #ENROLLMENT_CONFIRMATION} codes have none, since enabling the method is not itself part of a
 * login flow.
 */
public enum EmailOtpPurpose {
    ENROLLMENT_CONFIRMATION,
    LOGIN_CHALLENGE
}
