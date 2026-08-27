package com.ssoplatform.idp.application.usecase.user;

import java.util.UUID;

/**
 * Input for {@link RequestPasswordResetUseCase}.
 *
 * <p>Carries {@code tenantSlug} alongside {@code tenantId} for the same reason {@link
 * RegisterUserCommand} does: the caller (an API/MVC controller reading from {@code
 * TenantContext}) has already resolved both, and the slug is needed to build the reset link
 * without this use case having to re-fetch the tenant just for its slug.
 */
public record RequestPasswordResetCommand(UUID tenantId, String tenantSlug, String email) {}
