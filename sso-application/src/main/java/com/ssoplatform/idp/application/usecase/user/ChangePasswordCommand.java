package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/**
 * Input for {@link ChangePasswordUseCase}. {@code userId} identifies whose password is being
 * changed - the caller (a controller) reads it from the already-authenticated {@code
 * SsoAuthenticatedPrincipal}, never from user-submitted input, so this use case can never be
 * tricked into changing a different account's password.
 */
public record ChangePasswordCommand(UUID userId, String currentRawPassword, String newRawPassword) {}
