package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Output of {@link LoginUseCase}: the identity that was authenticated. */
public record LoginResult(UUID userId, UUID tenantId, String email) {}
