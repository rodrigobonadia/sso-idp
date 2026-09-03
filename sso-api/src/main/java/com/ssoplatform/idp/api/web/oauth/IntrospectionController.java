package com.ssoplatform.idp.api.web.oauth;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.OAuthIntrospectionException;
import com.ssoplatform.idp.application.usecase.introspection.IntrospectTokenCommand;
import com.ssoplatform.idp.application.usecase.introspection.IntrospectTokenResult;
import com.ssoplatform.idp.application.usecase.introspection.IntrospectTokenUseCase;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code POST /introspect}: the OAuth2 Token Introspection endpoint (RFC 7662), letting a
 * resource server ask whether a token this platform issued is currently valid - see {@code
 * IntrospectTokenUseCase}'s Javadoc for the full validation rules and the enumeration-safety
 * reasoning behind always answering {@code {"active": false}} rather than a distinguishing error
 * for anything about the TOKEN itself.
 *
 * <p>Deliberately {@code permitAll} and CSRF-exempt in {@code SecurityConfig}, exactly like {@code
 * /token}: the caller authenticates as the OAuth CLIENT via hand-parsed HTTP Basic, never a Spring
 * Security session. {@link OAuthIntrospectionException} is the only exception this controller
 * catches - reserved for a request that cannot even be evaluated (missing {@code token}, or the
 * calling client's own credentials being wrong) - mapped by {@link #errorResponse} exactly like
 * {@code TokenController} does for {@code OAuthTokenException}: 401 with {@code WWW-Authenticate:
 * Basic} for {@code invalid_client}, 400 for {@code invalid_request}.
 *
 * <p>Always responds {@code 200 OK} for a request that COULD be evaluated, whether the token turns
 * out active or not - RFC 7662 never distinguishes the two at the HTTP layer, only in the body.
 */
@RestController
public class IntrospectionController {

    private static final String BASIC_PREFIX = "Basic ";

    private final IntrospectTokenUseCase introspectTokenUseCase;
    private final TenantContext tenantContext;

    public IntrospectionController(IntrospectTokenUseCase introspectTokenUseCase, TenantContext tenantContext) {
        this.introspectTokenUseCase = introspectTokenUseCase;
        this.tenantContext = tenantContext;
    }

    @PostMapping("/introspect")
    public ResponseEntity<?> introspect(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestParam(value = "token", required = false) String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint) {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);
        String[] clientCredentials = parseBasicAuth(authorizationHeader);

        IntrospectTokenCommand command = new IntrospectTokenCommand(
                tenant.tenantId(),
                token,
                tokenTypeHint,
                clientCredentials == null ? null : clientCredentials[0],
                clientCredentials == null ? null : clientCredentials[1]);

        try {
            IntrospectTokenResult result = introspectTokenUseCase.execute(command);
            return ResponseEntity.ok(new IntrospectionResponse(
                    result.active(),
                    result.scope(),
                    result.clientId(),
                    result.tokenType(),
                    result.exp(),
                    result.iat(),
                    result.sub(),
                    result.aud(),
                    result.iss(),
                    result.jti()));
        } catch (OAuthIntrospectionException ex) {
            return errorResponse(ex);
        }
    }

    private static ResponseEntity<OAuthErrorResponse> errorResponse(OAuthIntrospectionException ex) {
        ResponseEntity.BodyBuilder builder = "invalid_client".equals(ex.errorCode())
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, "Basic")
                : ResponseEntity.status(HttpStatus.BAD_REQUEST);
        return builder.body(new OAuthErrorResponse(ex.errorCode(), ex.getMessage()));
    }

    /** Mirrors {@code TokenController#parseBasicAuth} exactly. */
    private static String[] parseBasicAuth(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BASIC_PREFIX)) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(authorizationHeader.substring(BASIC_PREFIX.length()));
            String decodedCredentials = new String(decoded, StandardCharsets.UTF_8);
            int separatorIndex = decodedCredentials.indexOf(':');
            if (separatorIndex < 0) {
                return null;
            }
            return new String[] {
                decodedCredentials.substring(0, separatorIndex), decodedCredentials.substring(separatorIndex + 1)
            };
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
