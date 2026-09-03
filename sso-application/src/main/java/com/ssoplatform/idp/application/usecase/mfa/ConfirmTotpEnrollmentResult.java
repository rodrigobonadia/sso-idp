package com.ssoplatform.idp.application.usecase.mfa;

import java.util.List;

/**
 * Output of {@link ConfirmTotpEnrollmentUseCase}: the ten single-use recovery codes in plaintext -
 * the only moment they ever exist outside a hashed form. The caller (API layer) must show these to
 * the user once and never expose them again.
 */
public record ConfirmTotpEnrollmentResult(List<String> recoveryCodes) {}
