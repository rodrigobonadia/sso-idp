package com.ssoplatform.idp.domain.tenant;

/** Lifecycle status of a {@link Tenant}. */
public enum TenantStatus {

    /** Fully operational: users can authenticate and OAuth clients can request tokens. */
    ACTIVE,

    /** Temporarily disabled by an administrator: all authentication for this tenant is refused. */
    SUSPENDED
}
