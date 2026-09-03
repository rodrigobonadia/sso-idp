package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/mfa/disable}. */
public record MfaDisableRequest(String currentPassword) {}
