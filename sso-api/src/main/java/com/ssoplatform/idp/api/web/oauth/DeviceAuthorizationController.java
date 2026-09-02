package com.ssoplatform.idp.api.web.oauth;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.OAuthDeviceAuthorizationException;
import com.ssoplatform.idp.application.usecase.device.RequestDeviceAuthorizationCommand;
import com.ssoplatform.idp.application.usecase.device.RequestDeviceAuthorizationResult;
import com.ssoplatform.idp.application.usecase.device.RequestDeviceAuthorizationUseCase;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
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
 * {@code POST /device_authorization}: the device authorization endpoint (RFC 8628 §3.1) that
 * starts the Device Authorization Grant - see {@code RequestDeviceAuthorizationUseCase}'s Javadoc
 * for the full client-authentication and scope-validation rules. Deliberately {@code permitAll}
 * and CSRF-exempt in {@code SecurityConfig}, for the identical reason {@code TokenController} is:
 * the caller here is the OAuth CLIENT itself (via hand-parsed HTTP Basic, or - new in this grant -
 * a public client's bare {@code client_id} body parameter), never a browser session.
 *
 * <p>Mirrors {@code TokenController} in every other respect: a single {@link
 * OAuthDeviceAuthorizationException} catch block, {@link #errorResponse} mapping {@code
 * invalid_client} to HTTP 401 with {@code WWW-Authenticate: Basic} and everything else to 400, and
 * {@code Cache-Control: no-store}/{@code Pragma: no-cache} on both the success and error responses
 * (RFC 8628 §3.2 explicitly requires the same caching prohibition RFC 6749 §5.1/§5.2 impose on
 * {@code /token}).
 *
 * <p>{@link #buildVerificationUri} builds the tenant-scoped, absolute URL of {@code GET /device}
 * from the exact same {@code app.tenant.base-domain}/{@code app.mail.link-scheme}/{@code
 * server.port} configuration {@code TokenController} uses for its {@code iss} claim - composing a
 * URL from Spring configuration is a web-layer concern, not something the framework-free use case
 * should own (see {@code RequestDeviceAuthorizationCommand}'s Javadoc).
 */
@RestController
public class DeviceAuthorizationController {

    private static final String BASIC_PREFIX = "Basic ";

    private final RequestDeviceAuthorizationUseCase requestDeviceAuthorizationUseCase;
    private final TenantContext tenantContext;
    private final String tenantBaseDomain;
    private final String linkScheme;
    private final String serverPort;

    public DeviceAuthorizationController(
            RequestDeviceAuthorizationUseCase requestDeviceAuthorizationUseCase,
            TenantContext tenantContext,
            @Value("${app.tenant.base-domain}") String tenantBaseDomain,
            @Value("${app.mail.link-scheme:http}") String linkScheme,
            @Value("${server.port}") String serverPort) {
        this.requestDeviceAuthorizationUseCase = requestDeviceAuthorizationUseCase;
        this.tenantContext = tenantContext;
        this.tenantBaseDomain = tenantBaseDomain;
        this.linkScheme = linkScheme;
        this.serverPort = serverPort;
    }

    @PostMapping("/device_authorization")
    public ResponseEntity<?> requestDeviceAuthorization(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "scope", required = false) String scope) {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);
        String[] clientCredentials = parseBasicAuth(authorizationHeader);

        RequestDeviceAuthorizationCommand command = new RequestDeviceAuthorizationCommand(
                tenant.tenantId(),
                buildVerificationUri(tenant.slug()),
                clientId,
                scope,
                clientCredentials == null ? null : clientCredentials[0],
                clientCredentials == null ? null : clientCredentials[1]);

        try {
            RequestDeviceAuthorizationResult result = requestDeviceAuthorizationUseCase.execute(command);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .header(HttpHeaders.PRAGMA, "no-cache")
                    .body(new DeviceAuthorizationResponse(
                            result.deviceCode(),
                            result.userCode(),
                            result.verificationUri(),
                            result.verificationUriComplete(),
                            result.expiresInSeconds(),
                            result.interval()));
        } catch (OAuthDeviceAuthorizationException ex) {
            return errorResponse(ex);
        }
    }

    private static ResponseEntity<OAuthErrorResponse> errorResponse(OAuthDeviceAuthorizationException ex) {
        ResponseEntity.BodyBuilder builder = "invalid_client".equals(ex.errorCode())
                ? ResponseEntity.status(HttpStatus.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, "Basic")
                : ResponseEntity.status(HttpStatus.BAD_REQUEST);
        return builder
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(new OAuthErrorResponse(ex.errorCode(), ex.getMessage()));
    }

    private String buildVerificationUri(String tenantSlug) {
        return "%s://%s.%s:%s/device".formatted(linkScheme, tenantSlug, tenantBaseDomain, serverPort);
    }

    /** Returns {@code {clientId, clientSecret}}, or {@code null} if the header is absent or is
     * not well-formed HTTP Basic - mirrors {@code TokenController#parseBasicAuth} exactly. */
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
