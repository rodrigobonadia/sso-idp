package com.ssoplatform.idp.application.usecase.tenant;

import java.util.UUID;

/**
 * Output of {@link CreateTenantUseCase}. Deliberately a plain data carrier, not the
 * {@code Tenant} domain entity itself, so that interface adapters (e.g. REST controllers)
 * never get a handle on a mutable domain object.
 */
public record CreateTenantResult(UUID tenantId, String slug, String name) {}
