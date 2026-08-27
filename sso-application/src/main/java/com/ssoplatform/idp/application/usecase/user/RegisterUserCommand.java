package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/**
 * Input for {@link RegisterUserUseCase}.
 *
 * <p>Carries {@code tenantSlug} alongside {@code tenantId} even though the tenant could be
 * re-looked-up by id: the caller (an API/MVC controller reading from {@code TenantContext}) has
 * already resolved both, and the slug is needed to build the verification link without this use
 * case having to re-fetch the tenant just for its slug.
 */
public record RegisterUserCommand(UUID tenantId, String tenantSlug, String email, String rawPassword) {}
