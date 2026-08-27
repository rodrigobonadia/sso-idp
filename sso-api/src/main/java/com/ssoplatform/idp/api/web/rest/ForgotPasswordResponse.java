package com.ssoplatform.idp.api.web.rest;

/**
 * Response body for {@code POST /api/forgot-password}. Always the exact same fixed message,
 * regardless of whether the e-mail matched an account - see {@code RequestPasswordResetUseCase}'s
 * enumeration-safety rationale.
 */
public record ForgotPasswordResponse(String message) {

    private static final String FIXED_MESSAGE = "If that e-mail address is registered, a password reset link has been sent to it.";

    public ForgotPasswordResponse() {
        this(FIXED_MESSAGE);
    }
}
