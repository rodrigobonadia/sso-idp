package com.ssoplatform.idp.api.config;

import com.ssoplatform.idp.api.web.tenant.TenantResolutionFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.RequestContextFilter;

/**
 * Explicitly registers Spring's {@link RequestContextFilter}, ordered to run strictly before
 * {@link TenantResolutionFilter}.
 *
 * <p>A {@code Filter} runs before the servlet it wraps - here, {@code DispatcherServlet} - and it
 * is {@code DispatcherServlet} itself (a {@code FrameworkServlet}) that binds
 * {@link org.springframework.web.context.request.RequestContextHolder} for the current thread,
 * inside its own request processing. That means any {@code @RequestScope} bean (like
 * {@code TenantContext}) is NOT yet resolvable from a plain servlet {@code Filter} unless
 * something binds that context earlier. Without this bean, {@code TenantResolutionFilter} calling
 * {@code tenantContext.setTenant(...)} throws {@code IllegalStateException: No thread-bound
 * request found} the moment a real HTTP client (not MockMvc) hits a tenant subdomain - MockMvc
 * tests never caught this because Spring Test's {@code ServletTestExecutionListener} pre-binds
 * request attributes for the whole test thread, which a real embedded Tomcat request never does.
 */
@Configuration
public class WebFilterConfiguration {

    @Bean
    public FilterRegistrationBean<RequestContextFilter> requestContextFilter() {
        FilterRegistrationBean<RequestContextFilter> registration =
                new FilterRegistrationBean<>(new RequestContextFilter());
        registration.setOrder(TenantResolutionFilter.ORDER - 1);
        return registration;
    }
}
