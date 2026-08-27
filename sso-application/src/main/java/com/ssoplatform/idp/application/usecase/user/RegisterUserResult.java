package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Output of {@link RegisterUserUseCase}. */
public record RegisterUserResult(UUID userId, UUID tenantId, String email) {}
