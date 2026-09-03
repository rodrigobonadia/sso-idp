package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.ApplicationException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.user.LoginCommand;
import com.ssoplatform.idp.application.usecase.user.LoginOutcome;
import com.ssoplatform.idp.application.usecase.user.LoginUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Server-rendered login flow (Thymeleaf) and the placeholder post-login page. See {@code
 * AuthApiController} for the REST equivalent - both call {@link LoginUseCase} and then {@link
 * AuthenticatedSessionEstablisher} identically, so a session established through either surface
 * works on both.
 *
 * <p>{@code POST /login} redirects to {@code /account} after a successful sign-in UNLESS a request
 * was saved to the {@link RequestCache} before the user ever reached this form - which happens
 * exactly when {@code GET /authorize} (Phase 3.3) redirected an unauthenticated browser here (see
 * {@code SecurityConfig}'s Javadoc for how that save happens automatically). In that case, login
 * resumes the original {@code /authorize} request instead, exactly like Spring Security's own
 * {@code SavedRequestAwareAuthenticationSuccessHandler} would for a {@code .formLogin()} setup -
 * this project cannot use that class directly (no {@code AuthenticationSuccessHandler} is wired,
 * since login is not driven by Spring Security's {@code AuthenticationManager} at all - see this
 * class's other Javadoc paragraph), so the same behavior is replicated by hand here.
 */
@Controller
public class LoginPageController {

    private final LoginUseCase loginUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;
    private final TenantContext tenantContext;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public LoginPageController(
            LoginUseCase loginUseCase, AuthenticatedSessionEstablisher sessionEstablisher, TenantContext tenantContext) {
        this.loginUseCase = loginUseCase;
        this.sessionEstablisher = sessionEstablisher;
        this.tenantContext = tenantContext;
    }

    @GetMapping("/login")
    public String showLoginForm(Model model) {
        requireTenant();
        if (!model.containsAttribute("loginForm")) {
            model.addAttribute("loginForm", new LoginForm());
        }
        return "login";
    }

    @PostMapping("/login")
    public String submitLogin(
            @ModelAttribute("loginForm") LoginForm form,
            Model model,
            HttpServletRequest request,
            HttpServletResponse response) {
        TenantSummary tenant = requireTenant();
        try {
            LoginOutcome outcome =
                    loginUseCase.execute(new LoginCommand(tenant.tenantId(), form.getEmail(), form.getPassword()));
            return switch (outcome) {
                case LoginOutcome.Authenticated authenticated -> {
                    sessionEstablisher.establish(authenticated.result(), request, response);
                    yield "redirect:" + resolvePostLoginRedirect(request, response);
                }
                case LoginOutcome.MfaChallengeIssued issued -> {
                    // Kept entirely server-side (never a URL query parameter, which would leak it
                    // via browser history/Referer) - see MfaChallengePageController's Javadoc.
                    request.getSession(true)
                            .setAttribute(
                                    MfaChallengePageController.CHALLENGE_TOKEN_SESSION_ATTRIBUTE,
                                    issued.challengeToken());
                    yield "redirect:/login/mfa";
                }
            };
        } catch (ApplicationException ex) {
            // Covers InvalidCredentialsException/AccountNotVerifiedException/AccountLockedException/
            // AccountDisabledException: all user-facing login failures belong back on the form.
            model.addAttribute("errorMessage", ex.getMessage());
            return "login";
        }
    }

    @GetMapping("/account")
    public String showAccountPage(Model model, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        model.addAttribute("email", principal.email());
        return "account";
    }

    private TenantSummary requireTenant() {
        return tenantContext.tenant().orElseThrow(TenantRequiredException::new);
    }

    /**
     * Resumes a saved {@code /authorize} request if one exists for this session, per this class's
     * Javadoc; otherwise falls back to the ordinary post-login destination. The saved request is
     * removed from the cache either way it is consumed - if left in place, a later, UNRELATED
     * authentication (e.g. signing back in after a manual {@code /logout}) could incorrectly resume
     * a stale {@code /authorize} request from an earlier session.
     */
    private String resolvePostLoginRedirect(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest == null) {
            return "/account";
        }
        requestCache.removeRequest(request, response);
        return savedRequest.getRedirectUrl();
    }
}
