package com.ssoplatform.idp.application.usecase.mfa;

/** Output of {@link EnableEmailOtpUseCase}: a masked form of the address a confirmation code was
 * just sent to (e.g. {@code "j***n@example.com"}) - enough to reassure the user without fully
 * re-disclosing their own address on screen. */
public record EnableEmailOtpResult(String maskedEmail) {}
