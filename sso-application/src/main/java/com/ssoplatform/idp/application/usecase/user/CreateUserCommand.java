package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Input for {@link CreateUserUseCase}. */
public record CreateUserCommand(UUID tenantId, String email, String rawPassword) {}
