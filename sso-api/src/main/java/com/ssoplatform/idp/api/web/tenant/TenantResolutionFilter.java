package com.ssoplatform.idp.api.web.tenant;

import com.ssoplatform.idp.application.exception.TenantNotActiveException;
import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.usecase.tenant.ResolveActiveTenantBySlugUseCase;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Resolves the current tenant from the request's Host header (subdomain-based multi-tenancy,
 * e.g. {@code acme.ssoplatform.example}) before any controller runs, and rejects with a 404 any
 * request whose subdomain doesn't map to a known, active tenant.
 *
 * <p>Requests whose host has no subdomain at all (the platform's bare base domain - e.g. just
 * {@code localhost}, or {@code ssoplatform.example}) are let through with no tenant resolved:
 * this is the platform's "global" scope. {@code /actuator/**} is additionally exempted regardless
 * of host, since infrastructure/monitoring endpoints must keep working even for a host that isn't
 * a recognized tenant subdomain.
 *
 * <p>Registered with a very low {@link Order} value so it runs before essentially everything
 * else in the filter chain - in particular, before the authentication filter Phase 2.3 will add,
 * which will rely on {@link TenantContext} already being populated.
 */
@Component
@Order(TenantResolutionFilter.ORDER)
public class TenantResolutionFilter extends OncePerRequestFilter {

    /** Deliberately very early: this must run before authentication and every other concern. */
    public static final int ORDER = Integer.MIN_VALUE + 10;

    private static final String EXEMPT_PATH_PREFIX = "/actuator";

    private final ResolveActiveTenantBySlugUseCase resolveActiveTenantBySlugUseCase;
    private final TenantContext tenantContext;
    private final String baseDomain;

    public TenantResolutionFilter(
            ResolveActiveTenantBySlugUseCase resolveActiveTenantBySlugUseCase,
            TenantContext tenantContext,
            @Value("${app.tenant.base-domain}") String baseDomain) {
        this.resolveActiveTenantBySlugUseCase = resolveActiveTenantBySlugUseCase;
        this.tenantContext = tenantContext;
        this.baseDomain = baseDomain;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (isExempt(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<String> slug = TenantSlugExtractor.extract(request.getServerName(), baseDomain);
        if (slug.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            TenantSummary tenant = resolveActiveTenantBySlugUseCase.execute(slug.get());
            tenantContext.setTenant(tenant);
            filterChain.doFilter(request, response);
        } catch (TenantNotFoundException | TenantNotActiveException e) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown or inactive tenant");
        }
    }

    private boolean isExempt(HttpServletRequest request) {
        return request.getRequestURI().startsWith(EXEMPT_PATH_PREFIX);
    }
}
