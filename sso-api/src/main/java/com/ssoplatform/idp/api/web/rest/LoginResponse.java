package com.ssoplatform.idp.api.web.rest;

import java.util.UUID;

/**
 * Response body for {@code POST /api/login}. {@code status} discriminates the two shapes {@link
 * com.ssoplatform.idp.application.usecase.user.LoginOutcome} can produce: {@code "AUTHENTICATED"}
 * carries {@code userId}/{@code email} (a session has already been established), while {@code
 * "MFA_REQUIRED"} carries only {@code challengeToken} - the value to echo back to {@code
 * POST /api/mfa/challenge/totp} or {@code POST /api/mfa/challenge/recovery-code} to finish signing
 * in. This is a deliberate, intentionally breaking evolution of what was a single flat shape
 * before Phase 4.1 - acceptable since nothing external depends on this API yet.
 */
public record LoginResponse(String status, UUID userId, String email, String challengeToken) {

    public static LoginResponse authenticated(UUID userId, String email) {
        return new LoginResponse("AUTHENTICATED", userId, email, null);
    }

    public static LoginResponse mfaRequired(String challengeToken) {
        return new LoginResponse("MFA_REQUIRED", null, null, challengeToken);
    }
}
