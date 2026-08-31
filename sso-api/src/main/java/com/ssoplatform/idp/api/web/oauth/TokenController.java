package com.ssoplatform.idp.api.web.oauth;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.OAuthTokenException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.token.TokenCommand;
import com.ssoplatform.idp.application.usecase.token.TokenResult;
import com.ssoplatform.idp.application.usecase.token.TokenUseCase;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code POST /token}: the OAuth2/OIDC token endpoint, handling both the Authorization Code +
 * PKCE grant (RFC 6749 §4.1.3) and the Refresh Token grant (RFC 6749 §6) - see {@code
 * TokenUseCase}'s Javadoc for how the two are dispatched and how a new refresh token ends up on
 * this response. Deliberately {@code permitAll} in {@code SecurityConfig}, exactly like {@code
 * /.well-known/jwks.json} - this endpoint authenticates the CLIENT itself via HTTP Basic (parsed by
 * hand below, not via Spring Security's own {@code httpBasic()} DSL, matching how every other
 * authentication surface in this project hand-authenticates through a use case rather than a
 * Spring Security {@code AuthenticationProvider} - see {@code SecurityConfig}'s Javadoc), so there
 * is no resource-owner session for Spring Security to require here at all.
 *
 * <p>Unlike {@code AuthorizeController}, there is no redirect step and no "trusted vs untrusted
 * target" split: RFC 6749 §5.2 returns every error directly to the client as a JSON body, so
 * {@link OAuthTokenException} is the only exception this controller ever needs to catch, and
 * {@link #errorResponse} is the single place that maps its {@code errorCode()} to the right HTTP
 * status - 401 with {@code WWW-Authenticate: Basic} for {@code invalid_client} (client
 * authentication itself failed), 400 for everything else (RFC 6749 §5.2).
 *
 * <p>Both the success and error responses always carry {@code Cache-Control: no-store} and {@code
 * Pragma: no-cache} (RFC 6749 §5.1/§5.2) - a token response must never be cached by an intermediate
 * proxy.
 *
 * <p>The issuer URL passed into {@link TokenCommand} is built from the exact same {@code
 * app.tenant.base-domain} / {@code app.mail.link-scheme} / {@code server.port} configuration
 * {@code MockEmailSenderAdapter} already uses for tenant-scoped links - see {@code
 * TokenCommand}'s Javadoc for why that construction belongs here, in the web layer, rather than in
 * the framework-free {@code TokenUseCase}.
 */
@RestController
public class TokenController {

    private static final String BASIC_PREFIX = "Basic ";

    private final TokenUseCase tokenUseCase;
    private final TenantContext tenantContext;
    private final String tenantBaseDomain;
    private final String linkScheme;
    private final String serverPort;

    public TokenController(
            TokenUseCase tokenUseCase,
            TenantContext tenantContext,
            @Value("${app.tenant.base-domain}") String tenantBaseDomain,
            @Value("${app.mail.link-scheme:http}") String linkScheme,
            @Value("${server.port}") String serverPort) {
        this.tokenUseCase = tokenUseCase;
        this.tenantContext = tenantContext;
        this.tenantBaseDomain = tenantBaseDomain;
        this.linkScheme = linkScheme;
        this.serverPort = serverPort;
    }

    @PostMapping("/token")
    public ResponseEntity<?> token(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshToken) {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);
        String[] clientCredentials = parseBasicAuth(authorizationHeader);

        TokenCommand command = new TokenCommand(
                tenant.tenantId(),
                buildIssuer(tenant.slug()),
                grantType,
                code,
                redirectUri,
                codeVerifier,
                refreshToken,
                clientCredentials == null ? null : clientCredentials[0],
                clientCredentials == null ? null : clientCredentials[1]);

        try {
            TokenResult result = tokenUseCase.execute(command);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .header(HttpHeaders.PRAGMA, "no-cache")
                    .body(new TokenResponse(
                            result.accessToken(),
                            "Bearer",
                            result.expiresInSeconds(),
                            result.idToken(),
                            result.refreshToken()));
        } catch (OAuthTokenException ex) {
            return errorResponse(ex);
        }
    }

    private static ResponseEntity<OAuthErrorResponse> errorResponse(OAuthTokenException ex) {
        ResponseEntity.BodyBuilder builder = "invalid_client".equals(ex.errorCode())
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, "Basic")
                : ResponseEntity.status(HttpStatus.BAD_REQUEST);
        return builder
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(new OAuthErrorResponse(ex.errorCode(), ex.getMessage()));
    }

    private String buildIssuer(String tenantSlug) {
        return "%s://%s.%s:%s".formatted(linkScheme, tenantSlug, tenantBaseDomain, serverPort);
    }

    /** Returns {@code {clientId, clientSecret}}, or {@code null} if the header is absent or is
     * not well-formed HTTP Basic - {@link TokenUseCase} treats every such case identically as
     * {@code invalid_client}, so no finer-grained signal is needed here. */
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
