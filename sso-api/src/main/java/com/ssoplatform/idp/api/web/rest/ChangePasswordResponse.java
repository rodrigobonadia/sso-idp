package com.ssoplatform.idp.api.web.rest;

import java.util.UUID;

/** Response body for {@code POST /api/account/change-password}. */
public record ChangePasswordResponse(UUID userId, String email) {}
