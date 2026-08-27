package com.ssoplatform.idp.api.web.rest;

import java.util.UUID;

/** Response body for {@code POST /api/verify-email}. */
public record VerifyEmailResponse(UUID userId, String email) {}
