package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Input for {@link LoginUseCase}. */
public record LoginCommand(UUID tenantId, String email, String rawPassword) {}
