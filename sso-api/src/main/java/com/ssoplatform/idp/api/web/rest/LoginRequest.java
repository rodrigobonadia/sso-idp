package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/login}. */
public record LoginRequest(String email, String password) {}
