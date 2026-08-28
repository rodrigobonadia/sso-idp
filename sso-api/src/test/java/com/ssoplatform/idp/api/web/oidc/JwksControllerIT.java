package com.ssoplatform.idp.api.web.oidc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyCommand;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyUseCase;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantResult;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Exercises {@code GET /.well-known/jwks.json} end-to-end: real Spring context, real Postgres via
 * Testcontainers. Signing keys are seeded by calling {@link GenerateSigningKeyUseCase} directly
 * (like {@code AuthApiControllerIT} seeds tenants via {@link CreateTenantUseCase} directly) rather
 * than through {@code POST /internal/signing-keys}, since key generation itself is exercised by
 * {@code InternalSigningKeyControllerIT}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class JwksControllerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

    @Autowired
    private GenerateSigningKeyUseCase generateSigningKeyUseCase;

    @Test
    void returnsAnEmptyKeySetWhenTheTenantHasNoSigningKeyYet() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-jwks-empty"));

        mockMvc.perform(get("/.well-known/jwks.json")
                        .with(request -> {
                            request.setServerName("acme-jwks-empty.localhost");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys").isEmpty());
    }

    @Test
    void publishesTheCurrentSigningKeyAsAValidRsaJwk() throws Exception {
        CreateTenantResult tenant = createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-jwks-one"));
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));

        mockMvc.perform(get("/.well-known/jwks.json")
                        .with(request -> {
                            request.setServerName("acme-jwks-one.localhost");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys.length()").value(1))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty());
    }

    @Test
    void publishesBothTheCurrentAndARetiredKeyAfterRotation() throws Exception {
        CreateTenantResult tenant =
                createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-jwks-rotated"));
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));
        generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));

        mockMvc.perform(get("/.well-known/jwks.json")
                        .with(request -> {
                            request.setServerName("acme-jwks-rotated.localhost");
                            return request;
                        }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys.length()").value(2));
    }

    @Test
    void rejectsARequestWithNoTenantSubdomainAsBadRequest() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json")
                        .with(request -> {
                            request.setServerName("localhost");
                            return request;
                        }))
                .andExpect(status().isBadRequest());
    }

    @Test
    void isReachableWithoutAnyAuthenticatedSession() throws Exception {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-jwks-public"));

        // No .with(csrf())/session(...) at all - a GET to a permitAll path must not be blocked by
        // Spring Security, proving the JWKS document really is publicly fetchable.
        mockMvc.perform(get("/.well-known/jwks.json")
                        .with(request -> {
                            request.setServerName("acme-jwks-public.localhost");
                            return request;
                        }))
                .andExpect(status().isOk());
    }
}
