package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/mfa/totp/confirm}. */
public record MfaConfirmRequest(String code) {}
