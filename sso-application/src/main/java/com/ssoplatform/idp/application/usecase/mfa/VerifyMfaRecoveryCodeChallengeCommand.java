package com.ssoplatform.idp.application.usecase.mfa;

/** Input for {@link VerifyMfaRecoveryCodeChallengeUseCase}: the raw challenge token from {@code
 * LoginOutcome.MfaChallengeIssued}, plus one of the user's recovery codes. */
public record VerifyMfaRecoveryCodeChallengeCommand(String challengeToken, String recoveryCode) {}
