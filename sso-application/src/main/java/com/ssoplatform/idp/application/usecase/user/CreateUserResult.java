package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Output of {@link CreateUserUseCase}. */
public record CreateUserResult(UUID userId, UUID tenantId, String email) {}
