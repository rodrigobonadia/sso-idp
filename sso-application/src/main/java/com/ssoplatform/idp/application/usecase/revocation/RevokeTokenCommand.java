package com.ssoplatform.idp.application.usecase.revocation;

import java.util.UUID;

/**
 * Input to {@link RevokeTokenUseCase}: the raw token string presented for {@code POST /revoke}
 * (RFC 7009 §2.1), the optional (and, per this use case, unused) {@code token_type_hint}, the
 * tenant resolved for the request, and the calling client's HTTP Basic credentials.
 */
public record RevokeTokenCommand(
        UUID tenantId, String token, String tokenTypeHint, String basicAuthClientId, String basicAuthClientSecret) {}
