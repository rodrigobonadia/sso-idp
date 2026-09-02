package com.ssoplatform.idp.application.usecase.device;

/**
 * Output of a successful {@link FindDeviceAuthorizationUseCase#execute}: just enough for the
 * verification page to render its Allow/Deny confirmation - the OAuth client's display {@link
 * #clientName} and the {@link #userCode} formatted for display. Deliberately does not expose the
 * requested scopes: this platform shows no consent screen anywhere (see {@code
 * architecture_decisions.md}), so the device verification page does not either, for consistency.
 */
public record DeviceAuthorizationView(String userCode, String clientName) {}
