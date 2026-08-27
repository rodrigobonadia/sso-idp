package com.ssoplatform.idp.application.usecase.tenant;

import java.util.UUID;

/**
 * Output of {@link ResolveActiveTenantBySlugUseCase}: the minimal, presentation-safe tenant data
 * a caller needs once a tenant has been resolved and confirmed active. Deliberately not the
 * {@code Tenant} domain entity itself - see {@link CreateTenantResult} for the same rationale.
 */
public record TenantSummary(UUID tenantId, String slug, String name) {}
