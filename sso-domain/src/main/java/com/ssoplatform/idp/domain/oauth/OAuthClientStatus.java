package com.ssoplatform.idp.domain.oauth;

/** Lifecycle status of an {@link OAuthClient}. Mirrors {@code TenantStatus}'s two-state shape. */
public enum OAuthClientStatus {
    /** The client may be used in any OAuth2/OIDC flow. */
    ACTIVE,
    /** The client is administratively disabled: every flow must reject it (e.g. a compromised
     * client secret), without deleting its registration/history. */
    DISABLED
}
