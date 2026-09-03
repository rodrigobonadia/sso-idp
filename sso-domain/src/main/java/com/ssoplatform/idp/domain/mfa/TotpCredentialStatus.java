package com.ssoplatform.idp.domain.mfa;

/**
 * Lifecycle of a {@link TotpCredential}. {@code PENDING_ACTIVATION} is a freshly generated secret
 * that has not yet been proven to actually work on the user's authenticator app - it cannot be
 * used to satisfy a login challenge until {@link TotpCredential#activate} moves it to {@code
 * ACTIVE}. There is no "disabled"/"retired" terminal status (unlike {@code SigningKeyStatus}):
 * disabling MFA has no audit value in keeping the old secret around (nothing needs to keep
 * verifying against it), so it is a hard delete instead - see {@code DisableMfaUseCase}.
 */
public enum TotpCredentialStatus {
    PENDING_ACTIVATION,
    ACTIVE
}
