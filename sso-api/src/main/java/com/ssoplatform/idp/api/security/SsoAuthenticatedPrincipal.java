package com.ssoplatform.idp.api.security;

import java.util.Objects;
import java.util.UUID;
import org.springframework.security.core.AuthenticatedPrincipal;

/**
 * The authenticated identity stored in Spring Security's {@code SecurityContext} once {@link
 * AuthenticatedSessionEstablisher} establishes a session.
 *
 * <p>Deliberately implements only {@link AuthenticatedPrincipal} - the minimal, name-only contract
 * - rather than {@code UserDetails}: this system has no {@code UserDetailsService} (per-tenant
 * e-mail uniqueness does not fit its single global-username assumption), so there is no framework
 * "user loading" step to satisfy. All the real authentication logic already ran in {@link
 * com.ssoplatform.idp.application.usecase.user.LoginUseCase}; this type only carries its result
 * into the security context for the rest of the request (and later requests, once persisted).
 */
public final class SsoAuthenticatedPrincipal implements AuthenticatedPrincipal {

    private final UUID userId;
    private final UUID tenantId;
    private final String email;

    public SsoAuthenticatedPrincipal(UUID userId, UUID tenantId, String email) {
        this.userId = Objects.requireNonNull(userId, "userId must not be null");
        this.tenantId = Objects.requireNonNull(tenantId, "tenantId must not be null");
        this.email = Objects.requireNonNull(email, "email must not be null");
    }

    @Override
    public String getName() {
        return email;
    }

    public UUID userId() {
        return userId;
    }

    public UUID tenantId() {
        return tenantId;
    }

    public String email() {
        return email;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SsoAuthenticatedPrincipal that)) return false;
        return userId.equals(that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId);
    }

    @Override
    public String toString() {
        // Deliberately omits nothing sensitive - just an identity marker, no credentials involved.
        return "SsoAuthenticatedPrincipal{userId=" + userId + ", tenantId=" + tenantId + ", email=" + email + "}";
    }
}
