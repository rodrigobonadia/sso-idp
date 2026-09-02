package com.ssoplatform.idp.api.web.oauth;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.InvalidBearerTokenException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.userinfo.GetUserInfoCommand;
import com.ssoplatform.idp.application.usecase.userinfo.GetUserInfoUseCase;
import com.ssoplatform.idp.application.usecase.userinfo.UserInfoResult;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code GET /userinfo}: the OIDC UserInfo endpoint (OpenID Connect Core 1.0 §5.3), returning
 * whichever claims the presented bearer access token's {@code scope} grants - see {@code
 * GetUserInfoUseCase}'s Javadoc for the full validation and scope-gating rules.
 *
 * <p>Deliberately {@code permitAll} in {@code SecurityConfig}, exactly like {@code /token}: there
 * is no resource-owner SESSION to require here - the caller authenticates via the {@code
 * Authorization} header's bearer token instead, hand-parsed below (not via Spring Security's
 * {@code oauth2ResourceServer()} DSL, matching how every other authentication surface in this
 * project hand-authenticates through a use case rather than a Spring Security {@code
 * AuthenticationProvider}).
 *
 * <p>Every failure is reported per RFC 6750 §3: a {@code WWW-Authenticate: Bearer error="..."}
 * challenge, with the HTTP status {@link #errorResponse} maps from {@link
 * InvalidBearerTokenException#errorCode()} - 400 for {@code invalid_request} (the header is
 * missing/malformed), 401 for {@code invalid_token} (the token itself does not verify), 403 for
 * {@code insufficient_scope} (the token verifies but was not issued with {@code openid}).
 */
@RestController
public class UserInfoController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final GetUserInfoUseCase getUserInfoUseCase;
    private final TenantContext tenantContext;

    public UserInfoController(GetUserInfoUseCase getUserInfoUseCase, TenantContext tenantContext) {
        this.getUserInfoUseCase = getUserInfoUseCase;
        this.tenantContext = tenantContext;
    }

    @GetMapping("/userinfo")
    public ResponseEntity<?> userInfo(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader) {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);

        try {
            UserInfoResult result = getUserInfoUseCase.execute(
                    new GetUserInfoCommand(tenant.tenantId(), parseBearerToken(authorizationHeader)));
            return ResponseEntity.ok(new UserInfoResponse(
                    result.sub(),
                    result.email(),
                    result.emailVerified(),
                    result.givenName(),
                    result.familyName(),
                    result.name()));
        } catch (InvalidBearerTokenException ex) {
            return errorResponse(ex);
        }
    }

    private static ResponseEntity<OAuthErrorResponse> errorResponse(InvalidBearerTokenException ex) {
        HttpStatus status =
                switch (ex.errorCode()) {
                    case "invalid_token" -> HttpStatus.UNAUTHORIZED;
                    case "insufficient_scope" -> HttpStatus.FORBIDDEN;
                    default -> HttpStatus.BAD_REQUEST;
                };
        String challenge = "Bearer error=\"%s\", error_description=\"%s\"".formatted(ex.errorCode(), ex.getMessage());
        return ResponseEntity.status(status)
                .header(HttpHeaders.WWW_AUTHENTICATE, challenge)
                .body(new OAuthErrorResponse(ex.errorCode(), ex.getMessage()));
    }

    /** Returns the raw token with the {@code "Bearer "} prefix stripped, or {@code null} if the
     * header is absent or does not start with that prefix - {@link GetUserInfoUseCase} treats a
     * {@code null}/blank token identically as {@code invalid_request}, so no finer-grained signal
     * is needed here. */
    private static String parseBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorizationHeader.substring(BEARER_PREFIX.length());
    }
}
