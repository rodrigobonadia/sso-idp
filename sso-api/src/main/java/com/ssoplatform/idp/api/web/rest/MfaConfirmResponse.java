package com.ssoplatform.idp.api.web.rest;

import java.util.List;

/** Response body for {@code POST /api/mfa/totp/confirm}: the ten recovery codes, in plaintext,
 * exactly once - see {@code ConfirmTotpEnrollmentResult}. */
public record MfaConfirmResponse(List<String> recoveryCodes) {}
