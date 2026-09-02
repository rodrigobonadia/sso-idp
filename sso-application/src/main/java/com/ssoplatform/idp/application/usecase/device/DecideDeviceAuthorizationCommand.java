package com.ssoplatform.idp.application.usecase.device;

import java.util.UUID;

/**
 * Input to {@link DecideDeviceAuthorizationUseCase}: the {@code user_code} the verification page
 * already confirmed resolves to a pending device code (via {@link FindDeviceAuthorizationUseCase}),
 * the {@link #decision} the authenticated user made (Allow or Deny), and that user's own id - the
 * web layer resolves both {@link #userId} and {@link #tenantId} from the already-authenticated
 * session, exactly like {@code AuthorizeCommand#userId} does.
 */
public record DecideDeviceAuthorizationCommand(
        UUID tenantId, UUID userId, String rawUserCode, DeviceAuthorizationDecision decision) {}
