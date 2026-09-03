package com.ssoplatform.idp.application.usecase.mfa;

import java.util.UUID;

/** Input for {@link ConfirmEmailOtpEnrollmentUseCase}. */
public record ConfirmEmailOtpEnrollmentCommand(UUID userId, String code) {}
