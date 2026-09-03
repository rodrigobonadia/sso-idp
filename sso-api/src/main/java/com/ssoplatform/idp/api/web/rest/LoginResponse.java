package com.ssoplatform.idp.api.web.rest;

import com.ssoplatform.idp.domain.mfa.MfaMethod;
import java.util.UUID;

/**
 * Response body for {@code POST /api/login}. {@code status} discriminates the two shapes {@link
 * com.ssoplatform.idp.application.usecase.user.LoginOutcome} can produce: {@code "AUTHENTICATED"}
 * carries {@code userId}/{@code email} (a session has already been established), while {@code
 * "MFA_REQUIRED"} carries {@code challengeToken} - the value to echo back to whichever of {@code
 * POST /api/mfa/challenge/totp}, {@code POST /api/mfa/challenge/email-otp}, or {@code POST
 * /api/mfa/challenge/recovery-code} matches {@code mfaMethod} - plus {@code mfaMethod} itself
 * ({@code "TOTP"} or {@code "EMAIL_OTP"}, added Phase 4.2) so the caller knows which primary factor
 * to prompt for without any separate lookup; a recovery code is always accepted as a fallback for
 * either. This is a deliberate, intentionally breaking evolution of what was a single flat shape
 * before Phase 4.1 - acceptable since nothing external depends on this API yet.
 */
public record LoginResponse(String status, UUID userId, String email, String challengeToken, MfaMethod mfaMethod) {

    public static LoginResponse authenticated(UUID userId, String email) {
        return new LoginResponse("AUTHENTICATED", userId, email, null, null);
    }

    public static LoginResponse mfaRequired(String challengeToken, MfaMethod mfaMethod) {
        return new LoginResponse("MFA_REQUIRED", null, null, challengeToken, mfaMethod);
    }
}
