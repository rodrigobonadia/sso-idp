package com.ssoplatform.idp.application.usecase.introspection;

import java.util.UUID;

/**
 * Input to {@link IntrospectTokenUseCase}: the raw token string presented for {@code POST
 * /introspect} (RFC 7662 §2.1), the optional {@code token_type_hint} (used only to decide which
 * lookup to try first - see the use case's Javadoc), the tenant resolved for the request, and the
 * calling client's HTTP Basic credentials.
 */
public record IntrospectTokenCommand(
        UUID tenantId,
        String token,
        String tokenTypeHint,
        String basicAuthClientId,
        String basicAuthClientSecret) {}
