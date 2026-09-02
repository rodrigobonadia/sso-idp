package com.ssoplatform.idp.application.usecase.userinfo;

import java.util.UUID;

/**
 * Input for {@link GetUserInfoUseCase}.
 *
 * <p>{@code tenantId} comes from {@code TenantContext} (the request's Host header), exactly like
 * every other tenant-scoped use case - NOT decoded from the bearer token itself, since this
 * platform's signing keys (and thus verification) are already tenant-scoped one layer down (see
 * {@code SigningKeyRepository#findAllByTenantId}). {@code bearerToken} is the raw {@code
 * Authorization: Bearer <token>} header value, with the {@code "Bearer "} prefix already stripped
 * by the controller.
 */
public record GetUserInfoCommand(UUID tenantId, String bearerToken) {}
