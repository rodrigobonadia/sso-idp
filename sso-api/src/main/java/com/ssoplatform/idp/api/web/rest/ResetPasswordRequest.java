package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/reset-password}. */
public record ResetPasswordRequest(String token, String newPassword) {}
