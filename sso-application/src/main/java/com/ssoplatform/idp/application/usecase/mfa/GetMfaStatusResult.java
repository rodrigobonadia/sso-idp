package com.ssoplatform.idp.application.usecase.mfa;

/** Output of {@link GetMfaStatusUseCase}: whether the user currently has an ACTIVE TOTP
 * credential. A PENDING_ACTIVATION (unconfirmed) credential counts as {@code false} - it cannot
 * satisfy a login challenge yet, so from the user's point of view MFA is not really "on". */
public record GetMfaStatusResult(boolean enabled) {}
