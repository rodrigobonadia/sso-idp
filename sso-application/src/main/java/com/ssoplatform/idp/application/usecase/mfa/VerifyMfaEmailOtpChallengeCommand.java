package com.ssoplatform.idp.application.usecase.mfa;

/** Input for {@link VerifyMfaEmailOtpChallengeUseCase}: the raw challenge token from {@code
 * LoginOutcome.MfaChallengeIssued}, plus the 6-digit code e-mailed to the user. */
public record VerifyMfaEmailOtpChallengeCommand(String challengeToken, String code) {}
