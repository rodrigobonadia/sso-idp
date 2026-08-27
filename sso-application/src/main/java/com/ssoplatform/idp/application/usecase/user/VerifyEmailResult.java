package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Output of {@link VerifyEmailUseCase}. */
public record VerifyEmailResult(UUID userId, String email) {}
