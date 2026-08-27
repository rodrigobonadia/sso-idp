package com.ssoplatform.idp.api.web.tenant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantId;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises {@link TenantResolutionFilter} end-to-end (real Spring filter chain, real Postgres
 * via Testcontainers) against a throwaway {@code /ping} endpoint registered only for this test -
 * Phase 2.1 doesn't add any real controller yet, and the filter's behavior doesn't depend on
 * which controller eventually runs.
 *
 * <p>{@code /ping} is exempted from Spring Security via a test-only {@link WebSecurityCustomizer}
 * (see {@link TestSecurityConfig}): this test is deliberately isolating {@link
 * TenantResolutionFilter}'s own behavior (200/404 based on tenant resolution), which runs as an
 * ordinary servlet {@code Filter} independent of - and before - Spring Security's filter chain
 * (see {@code WebFilterConfiguration}), so it is unaffected by this exemption. Since Phase 2.3
 * added real authentication, {@code /ping} would otherwise get a 403 from {@code
 * anyRequest().authenticated()} for having no real route in the production security policy.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import({TenantResolutionFilterIT.PingController.class, TenantResolutionFilterIT.TestSecurityConfig.class})
@Testcontainers
class TenantResolutionFilterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

    @Autowired
    private TenantRepository tenantRepository;

    @Test
    void allowsTheRequestThroughAndResolvesTheTenantForAnActiveTenantSubdomain() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-filter-it"));

        mockMvc.perform(get("/ping").with(request -> {
                    request.setServerName("acme-filter-it.localhost");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string("pong"));
    }

    @Test
    void rejectsWithNotFoundWhenTheSubdomainMatchesNoTenant() throws Exception {
        mockMvc.perform(get("/ping").with(request -> {
                    request.setServerName("no-such-tenant.localhost");
                    return request;
                }))
                .andExpect(status().isNotFound());
    }

    @Test
    void rejectsWithNotFoundWhenTheSubdomainMatchesASuspendedTenant() throws Exception {
        var created = createTenantUseCase.execute(new CreateTenantCommand("Suspended Corp", "acme-suspended-it"));
        // There is no SuspendTenantUseCase yet (that's an admin-console concern, Phase 6), so the
        // test suspends the tenant directly through the domain entity and the repository port -
        // both already fully available to sso-api.
        Tenant tenant = tenantRepository.findById(TenantId.of(created.tenantId())).orElseThrow();
        tenant.suspend();
        tenantRepository.save(tenant);

        mockMvc.perform(get("/ping").with(request -> {
                    request.setServerName("acme-suspended-it.localhost");
                    return request;
                }))
                .andExpect(status().isNotFound());
    }

    @Test
    void allowsTheRequestThroughWithNoTenantWhenTheHostHasNoSubdomain() throws Exception {
        mockMvc.perform(get("/ping").with(request -> {
                    request.setServerName("localhost");
                    return request;
                }))
                .andExpect(status().isOk())
                .andExpect(content().string("pong"));
    }

    @Test
    void alwaysExemptsActuatorEndpointsRegardlessOfHost() throws Exception {
        mockMvc.perform(get("/actuator/health").with(request -> {
                    request.setServerName("no-such-tenant.localhost");
                    return request;
                }))
                .andExpect(status().isOk());
    }

    @RestController
    static class PingController {

        @GetMapping("/ping")
        String ping() {
            return "pong";
        }
    }

    @TestConfiguration
    static class TestSecurityConfig {

        @Bean
        WebSecurityCustomizer pingIsExemptFromSecurity() {
            return web -> web.ignoring().requestMatchers("/ping");
        }
    }
}
