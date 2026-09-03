package com.ssoplatform.idp.api.web.rest;

/** Response body for {@code POST /api/mfa/totp/enroll}. */
public record MfaEnrollResponse(String secretBase32, String otpauthUri) {}
