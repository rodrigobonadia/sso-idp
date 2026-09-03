package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.domain.mfa.MfaMethod;

/** Output of {@link GetMfaStatusUseCase}. {@code method} is {@code null} whenever {@code enabled}
 * is {@code false} - there is nothing active to name a method for. A {@code PENDING_ACTIVATION}
 * (unconfirmed) credential of either method counts as {@code enabled == false} - it cannot satisfy
 * a login challenge yet, so from the user's point of view MFA is not really "on". */
public record GetMfaStatusResult(boolean enabled, MfaMethod method) {}
