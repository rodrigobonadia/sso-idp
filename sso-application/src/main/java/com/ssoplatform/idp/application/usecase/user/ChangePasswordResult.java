package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/** Output of {@link ChangePasswordUseCase}. */
public record ChangePasswordResult(UUID userId, String email) {}
