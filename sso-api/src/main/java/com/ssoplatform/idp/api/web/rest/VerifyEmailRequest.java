package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/verify-email}. */
public record VerifyEmailRequest(String token) {}
