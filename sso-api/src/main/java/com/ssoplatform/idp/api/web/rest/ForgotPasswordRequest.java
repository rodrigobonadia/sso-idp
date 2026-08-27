package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/forgot-password}. */
public record ForgotPasswordRequest(String email) {}
