package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/mfa/challenge/email-otp}. */
public record MfaEmailOtpChallengeRequest(String challengeToken, String code) {}
