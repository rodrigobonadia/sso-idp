package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/account/change-password}. */
public record ChangePasswordRequest(String currentPassword, String newPassword) {}
