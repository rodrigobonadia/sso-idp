package com.ssoplatform.idp.application.usecase.mfa;

import java.util.UUID;

/** Input for {@link DisableMfaUseCase}. Requires the current password as re-authentication
 * evidence - see the use case's Javadoc. */
public record DisableMfaCommand(UUID userId, String currentRawPassword) {}
