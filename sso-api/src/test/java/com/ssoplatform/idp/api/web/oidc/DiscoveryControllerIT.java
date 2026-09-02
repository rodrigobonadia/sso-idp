package com.ssoplatform.idp.api.web.oidc;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises {@code GET /.well-known/openid-configuration} end-to-end: real Spring context, real
 * Postgres via Testcontainers (needed only to resolve the tenant by subdomain, exactly like
 * {@code JwksControllerIT}).
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class DiscoveryControllerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

    @Test
    void publishesADiscoveryDocumentScopedToTheTenantsSubdomain() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-discovery"));

        mockMvc.perform(get("/.well-known/openid-configuration")
                        .with(request -> {
                            request.setServerName("acme-discovery.localhost");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("http://acme-discovery.localhost:8080"))
                .andExpect(jsonPath("$.authorization_endpoint")
                        .value("http://acme-discovery.localhost:8080/authorize"))
                .andExpect(jsonPath("$.token_endpoint").value("http://acme-discovery.localhost:8080/token"))
                .andExpect(jsonPath("$.jwks_uri")
                        .value("http://acme-discovery.localhost:8080/.well-known/jwks.json"))
                .andExpect(jsonPath("$.userinfo_endpoint").value("http://acme-discovery.localhost:8080/userinfo"));
    }

    @Test
    void advertisesExactlyTheCapabilitiesThisServerImplementsToday() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-discovery-caps"));

        mockMvc.perform(get("/.well-known/openid-configuration")
                        .with(request -> {
                            request.setServerName("acme-discovery-caps.localhost");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopes_supported").value(containsInAnyOrder("openid", "profile", "email")))
                .andExpect(jsonPath("$.response_types_supported").value(contains("code")))
                .andExpect(jsonPath("$.grant_types_supported").value(contains("authorization_code")))
                .andExpect(jsonPath("$.subject_types_supported").value(contains("public")))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported").value(contains("RS256")))
                .andExpect(jsonPath("$.token_endpoint_auth_methods_supported").value(contains("client_secret_basic")))
                .andExpect(jsonPath("$.code_challenge_methods_supported").value(contains("S256")))
                .andExpect(jsonPath("$.revocation_endpoint").doesNotExist())
                .andExpect(jsonPath("$.introspection_endpoint").doesNotExist())
                .andExpect(jsonPath("$.registration_endpoint").doesNotExist());
    }

    @Test
    void rejectsARequestWithNoTenantSubdomainAsBadRequest() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration")
                        .with(request -> {
                            request.setServerName("localhost");
                            return request;
                        }))
                .andExpect(status().isBadRequest());
    }

    @Test
    void isReachableWithoutAnyAuthenticatedSession() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-discovery-public"));

        // No .with(csrf())/session(...) at all - a GET to a permitAll path must not be blocked by
        // Spring Security, proving the discovery document really is publicly fetchable.
        mockMvc.perform(get("/.well-known/openid-configuration")
                        .with(request -> {
                            request.setServerName("acme-discovery-public.localhost");
                            return request;
                        }))
                .andExpect(status().isOk());
    }
}
