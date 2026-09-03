package com.ssoplatform.idp.application.usecase.mfa;

import java.util.List;

/** Output of {@link ConfirmEmailOtpEnrollmentUseCase}: the ten single-use recovery codes in
 * plaintext - mirrors {@link ConfirmTotpEnrollmentResult} exactly (recovery codes are
 * method-agnostic). */
public record ConfirmEmailOtpEnrollmentResult(List<String> recoveryCodes) {}
