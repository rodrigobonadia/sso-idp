package com.ssoplatform.idp.application.usecase.device;

/**
 * Output of a successful {@link RequestDeviceAuthorizationUseCase#execute} (RFC 8628 §3.2's device
 * authorization response). {@link #deviceCode} is the raw, high-entropy value the device polls
 * {@code /token} with; {@link #userCode} is the short, human-typeable value formatted for display
 * (e.g. {@code WDJP-MX9K} - see {@code UserCode#formatted()}). {@link #verificationUriComplete} is
 * {@link #verificationUri} with {@code user_code} pre-filled as a query parameter, so a client
 * capable of rendering a QR code or a clickable link can skip the manual-entry step entirely (RFC
 * 8628 §3.3.1) - {@code null} is never returned here since this platform's verification page
 * always supports the pre-filled form.
 */
public record RequestDeviceAuthorizationResult(
        String deviceCode,
        String userCode,
        String verificationUri,
        String verificationUriComplete,
        long expiresInSeconds,
        long interval) {}
