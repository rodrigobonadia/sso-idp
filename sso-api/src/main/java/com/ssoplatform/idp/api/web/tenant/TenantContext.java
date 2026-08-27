package com.ssoplatform.idp.api.web.tenant;

import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import java.util.Optional;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

/**
 * Holds the tenant resolved for the current HTTP request (by {@link TenantResolutionFilter}), so
 * that controllers - and later, other request-scoped collaborators such as the login/session
 * machinery in Phase 2.3 - can find out "which tenant is this request for" without re-parsing the
 * Host header themselves.
 *
 * <p>Request-scoped: a fresh instance backs every request and is discarded once it completes.
 * When no tenant applies to the request (e.g. a root-domain or {@code /actuator/**} request),
 * {@link #tenant()} simply stays empty - this is a normal, expected state, not an error.
 */
@Component
@RequestScope
public class TenantContext {

    private TenantSummary tenant;

    public Optional<TenantSummary> tenant() {
        return Optional.ofNullable(tenant);
    }

    public void setTenant(TenantSummary tenant) {
        this.tenant = tenant;
    }
}
