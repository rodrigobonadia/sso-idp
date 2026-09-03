package com.ssoplatform.idp.application.usecase.introspection;

/**
 * Output of {@link IntrospectTokenUseCase} - the RFC 7662 §2.2 introspection response shape.
 * {@link #active} is the only field ever meaningful when {@code false}; every other field is
 * {@code null} in that case, per the spec ("the authorization server MAY respond with just the
 * active field set to false"). {@link #exp}/{@link #iat} are epoch seconds, matching every other
 * JWT-shaped timestamp this platform issues.
 */
public record IntrospectTokenResult(
        boolean active,
        String scope,
        String clientId,
        String tokenType,
        Long exp,
        Long iat,
        String sub,
        String aud,
        String iss,
        String jti) {

    /** The RFC 7662 §2.2 response for any token this endpoint will not vouch for - unknown,
     * expired, malformed, or belonging to a different client/tenant than the caller. */
    public static IntrospectTokenResult inactive() {
        return new IntrospectTokenResult(false, null, null, null, null, null, null, null, null, null);
    }
}
