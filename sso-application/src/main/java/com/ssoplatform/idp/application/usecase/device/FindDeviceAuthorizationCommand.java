package com.ssoplatform.idp.application.usecase.device;

import java.util.UUID;

/** Input to {@link FindDeviceAuthorizationUseCase}: the raw {@code user_code} a human typed into the verification page's form, plus the tenant resolved by the web layer. */
public record FindDeviceAuthorizationCommand(UUID tenantId, String rawUserCode) {}
