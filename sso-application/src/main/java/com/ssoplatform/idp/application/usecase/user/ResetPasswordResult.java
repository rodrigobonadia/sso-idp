package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Output of {@link ResetPasswordUseCase}. */
public record ResetPasswordResult(UUID userId, UUID tenantId, String email) {}
