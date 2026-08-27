package com.ssoplatform.idp.api.web.rest;

import java.util.UUID;

/** Response body for {@code POST /api/login}. */
public record LoginResponse(UUID userId, String email) {}
