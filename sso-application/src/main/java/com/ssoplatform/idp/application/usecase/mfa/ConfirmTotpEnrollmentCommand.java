package com.ssoplatform.idp.application.usecase.mfa;

import java.util.UUID;

/** Input for {@link ConfirmTotpEnrollmentUseCase}. */
public record ConfirmTotpEnrollmentCommand(UUID userId, String code) {}
