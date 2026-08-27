package com.ssoplatform.idp.application.usecase.user;

/** Input for {@link VerifyEmailUseCase}: the raw token value presented by the caller. */
public record VerifyEmailCommand(String rawToken) {}
