package com.ssoplatform.idp.application.usecase.mfa;

/**
 * Output of {@link EnrollTotpUseCase}: everything a client needs to let the user add this secret
 * to an authenticator app. {@code secretBase32} is for manual entry; {@code otpauthUri} is the
 * standard {@code otpauth://totp/...} URI most authenticator apps can scan directly as a QR code
 * (rendering the QR code image itself is a client-side concern, not this API's).
 */
public record EnrollTotpResult(String secretBase32, String otpauthUri) {}
