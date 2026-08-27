package com.ssoplatform.idp.api.web.rest;

import java.util.UUID;

/** Response body for {@code POST /api/register}. */
public record RegisterResponse(UUID userId, String email) {}
