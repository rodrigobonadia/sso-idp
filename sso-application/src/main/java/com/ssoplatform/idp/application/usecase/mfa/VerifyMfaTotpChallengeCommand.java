package com.ssoplatform.idp.application.usecase.mfa;

/** Input for {@link VerifyMfaTotpChallengeUseCase}: the raw challenge token from {@code
 * LoginOutcome.MfaChallengeIssued}, plus the 6-digit code from the user's authenticator app. */
public record VerifyMfaTotpChallengeCommand(String challengeToken, String code) {}
