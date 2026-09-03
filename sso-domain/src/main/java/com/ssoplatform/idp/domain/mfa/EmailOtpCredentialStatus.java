package com.ssoplatform.idp.domain.mfa;

/**
 * Lifecycle of an {@link EmailOtpCredential}. Mirrors {@link TotpCredentialStatus} exactly - a
 * {@code PENDING_ACTIVATION} row exists only long enough to prove the user actually received a
 * confirmation code at their registered address before it can satisfy a login challenge. There is
 * no "disabled"/"retired" terminal status here either, for the same reason: disabling MFA has no
 * audit value in keeping the row around - see {@code DisableMfaUseCase}.
 */
public enum EmailOtpCredentialStatus {
    PENDING_ACTIVATION,
    ACTIVE
}
