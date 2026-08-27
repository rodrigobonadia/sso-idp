package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/register}. */
public record RegisterRequest(String email, String password) {}
