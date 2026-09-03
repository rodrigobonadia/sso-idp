package com.ssoplatform.idp.application.usecase.mfa;

import java.util.UUID;

/** Input for {@link EnrollTotpUseCase}. */
public record EnrollTotpCommand(UUID userId) {}
