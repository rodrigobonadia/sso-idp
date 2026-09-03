package com.ssoplatform.idp.application.usecase.mfa;

import java.util.UUID;

/** Input for {@link EnableEmailOtpUseCase}. */
public record EnableEmailOtpCommand(UUID userId) {}
