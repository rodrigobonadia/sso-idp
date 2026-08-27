package com.ssoplatform.idp.api.web.rest;

import java.util.UUID;

/** Response body for {@code POST /api/reset-password}. */
public record ResetPasswordResponse(UUID userId, String email) {}
