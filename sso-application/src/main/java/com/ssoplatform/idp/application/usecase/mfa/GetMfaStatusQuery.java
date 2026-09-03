package com.ssoplatform.idp.application.usecase.mfa;

import java.util.UUID;

/** Input for {@link GetMfaStatusUseCase}. */
public record GetMfaStatusQuery(UUID userId) {}
