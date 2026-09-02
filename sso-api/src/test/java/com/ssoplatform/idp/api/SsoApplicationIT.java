package com.ssoplatform.idp.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.application.exception.DuplicateEmailException;
import com.ssoplatform.idp.application.exception.DuplicateTenantSlugException;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantResult;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.application.usecase.user.CreateUserCommand;
import com.ssoplatform.idp.application.usecase.user.CreateUserResult;
import com.ssoplatform.idp.application.usecase.user.CreateUserUseCase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * End-to-end smoke test for Phase 1: boots the full Spring context (Flyway migrations against a
 * real PostgreSQL container, JPA, the composition root in {@code UseCaseConfiguration}) and
 * drives the two use cases through their public API, exactly as an outer layer eventually will.
 *
 * <p>{@code classes = SsoApplication.class} is passed explicitly rather than relying on
 * {@code @SpringBootTest}'s default same-package auto-detection of a {@code @SpringBootConfiguration}
 * class, which was failing under Failsafe's forked-JVM classloader in this multi-module reactor
 * build with {@code IllegalStateException: Unable to find a @SpringBootConfiguration}, even though
 * {@code SsoApplication} sits in this exact package and compiles correctly.
 */
@SpringBootTest(classes = SsoApplication.class)
@Testcontainers
class SsoApplicationIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

    @Autowired
    private CreateUserUseCase createUserUseCase;

    @Test
    void springContextLoadsWithAllUseCasesWired() {
        assertThat(createTenantUseCase).isNotNull();
        assertThat(createUserUseCase).isNotNull();
    }

    @Test
    void registersATenantAndAUserEndToEndThroughRealPersistence() {
        CreateTenantResult tenant =
                createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-e2e-" + System.nanoTime()));

        CreateUserResult user = createUserUseCase.execute(
                new CreateUserCommand(tenant.tenantId(), "someone@example.com", "Jane", "Doe", "Str0ng!Passw0rd"));

        assertThat(user.tenantId()).isEqualTo(tenant.tenantId());
        assertThat(user.email()).isEqualTo("someone@example.com");
    }

    @Test
    void rejectsARepeatedTenantSlug() {
        String slug = "acme-duplicate-" + System.nanoTime();
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", slug));

        assertThatThrownBy(() -> createTenantUseCase.execute(new CreateTenantCommand("Acme Corp Again", slug)))
                .isInstanceOf(DuplicateTenantSlugException.class);
    }

    @Test
    void rejectsARepeatedEmailWithinTheSameTenant() {
        CreateTenantResult tenant = createTenantUseCase.execute(
                new CreateTenantCommand("Acme Corp", "acme-dup-email-" + System.nanoTime()));
        createUserUseCase.execute(
                new CreateUserCommand(tenant.tenantId(), "dup@example.com", "Jane", "Doe", "Str0ng!Passw0rd"));

        assertThatThrownBy(() -> createUserUseCase.execute(new CreateUserCommand(
                        tenant.tenantId(), "dup@example.com", "Jane", "Doe", "An0ther!Passw0rd")))
                .isInstanceOf(DuplicateEmailException.class);
    }
}
