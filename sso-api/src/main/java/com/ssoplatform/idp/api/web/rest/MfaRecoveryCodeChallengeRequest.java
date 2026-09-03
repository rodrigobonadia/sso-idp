package com.ssoplatform.idp.api.web.rest;

/** Request body for {@code POST /api/mfa/challenge/recovery-code}. */
public record MfaRecoveryCodeChallengeRequest(String challengeToken, String recoveryCode) {}
