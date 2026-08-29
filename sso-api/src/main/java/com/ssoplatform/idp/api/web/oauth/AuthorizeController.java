package com.ssoplatform.idp.api.web.oauth;

import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.OAuthAuthorizationException;
import com.ssoplatform.idp.application.exception.OAuthClientNotFoundException;
import com.ssoplatform.idp.application.exception.RedirectUriNotRegisteredException;
import com.ssoplatform.idp.application.usecase.authorization.AuthorizeCommand;
import com.ssoplatform.idp.application.usecase.authorization.AuthorizeResult;
import com.ssoplatform.idp.application.usecase.authorization.AuthorizeUseCase;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.domain.shared.DomainException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * {@code GET /authorize}: the OAuth2/OIDC authorization endpoint for the Authorization Code + PKCE
 * grant (RFC 6749 §4.1.1, PKCE per RFC 7636). Requires an authenticated session under this
 * project's default {@code anyRequest().authenticated()} rule (this path is deliberately NOT in
 * {@code SecurityConfig}'s {@code permitAll} list) - but unlike every other protected path, an
 * unauthenticated request here is redirected to {@code /login} and, once the user signs in,
 * automatically resumed back to this exact request (see {@code SecurityConfig}'s Javadoc for the
 * {@link org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint}
 * configured only for this path, and {@code LoginPageController}'s Javadoc for the resume side of
 * that flow) - the standard OAuth UX, rather than the plain 403 every other protected path gets.
 *
 * <p>There is no consent screen (a Phase 3 scope decision - see {@code architecture_decisions.md}):
 * once the request passes every validation {@link AuthorizeUseCase} performs, it is auto-approved
 * and the browser is redirected straight back to the client with a fresh authorization code.
 *
 * <p>Error handling follows RFC 6749 §4.1.2.1 exactly, which is why this method has two distinct
 * catch blocks rather than one: {@link OAuthAuthorizationException} means the {@code redirect_uri}
 * was already confirmed valid and registered, so the error is redirected back to the CLIENT
 * ({@code redirect_uri?error=...&error_description=...&state=...}); {@link
 * OAuthClientNotFoundException}, {@link RedirectUriNotRegisteredException}, and any other {@link
 * DomainException} (covering the domain-level {@code InvalidClientIdException}/{@code
 * InvalidRedirectUriException}) mean there is no confirmed-trustworthy redirect target at all, so
 * the resource owner sees a rendered error page instead - never a redirect built from unvalidated
 * input.
 *
 * <p>{@code nonce} (OpenID Connect Core 1.0 §3.1.2.1) is accepted but never validated here or by
 * {@link AuthorizeUseCase} - it is only captured onto the issued authorization code so that {@code
 * POST /token} (Phase 3.4) can echo it back as the {@code id_token} {@code nonce} claim. RECOMMENDED
 * but not REQUIRED for this grant, so it is {@code required = false}.
 */
@Controller
public class AuthorizeController {

    private final AuthorizeUseCase authorizeUseCase;
    private final TenantContext tenantContext;

    public AuthorizeController(AuthorizeUseCase authorizeUseCase, TenantContext tenantContext) {
        this.authorizeUseCase = authorizeUseCase;
        this.tenantContext = tenantContext;
    }

    @GetMapping("/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("response_type") String responseType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod,
            @RequestParam(value = "nonce", required = false) String nonce,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal,
            Model model) {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);

        AuthorizeCommand command = new AuthorizeCommand(
                tenant.tenantId(),
                principal.userId(),
                clientId,
                redirectUri,
                responseType,
                scope,
                state,
                codeChallenge,
                codeChallengeMethod,
                nonce);

        try {
            AuthorizeResult result = authorizeUseCase.execute(command);
            return "redirect:" + buildSuccessRedirect(result);
        } catch (OAuthAuthorizationException ex) {
            return "redirect:" + buildErrorRedirect(redirectUri, state, ex);
        } catch (OAuthClientNotFoundException | RedirectUriNotRegisteredException | DomainException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
            return "authorize-error";
        }
    }

    private static String buildSuccessRedirect(AuthorizeResult result) {
        UriComponentsBuilder builder =
                UriComponentsBuilder.fromUriString(result.redirectUri()).queryParam("code", result.code());
        if (result.state() != null) {
            builder.queryParam("state", result.state());
        }
        return builder.build().encode().toUriString();
    }

    private static String buildErrorRedirect(String redirectUri, String state, OAuthAuthorizationException ex) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", ex.errorCode())
                .queryParam("error_description", ex.getMessage());
        if (state != null) {
            builder.queryParam("state", state);
        }
        return builder.build().encode().toUriString();
    }
}
