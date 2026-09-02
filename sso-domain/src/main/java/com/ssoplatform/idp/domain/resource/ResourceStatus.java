package com.ssoplatform.idp.domain.resource;

/** Lifecycle status of a {@link Resource}. Mirrors {@code OAuthClientStatus}'s two-state shape. */
public enum ResourceStatus {
    /** The resource may be requested as an audience by any authorized client. */
    ACTIVE,
    /** The resource is administratively disabled: {@code /token} must reject every Client
     * Credentials request naming it, without deleting its registration/history. */
    DISABLED
}
