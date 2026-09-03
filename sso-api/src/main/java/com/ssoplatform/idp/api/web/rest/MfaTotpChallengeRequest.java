package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/mfa/challenge/totp}. */
public record MfaTotpChallengeRequest(String challengeToken, String code) {}
