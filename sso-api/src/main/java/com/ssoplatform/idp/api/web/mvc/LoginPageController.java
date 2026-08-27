package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.ApplicationException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.user.LoginCommand;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.application.usecase.user.LoginUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
 */
@Controller
public class LoginPageController {

    private final LoginUseCase loginUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;
    private final TenantContext tenantContext;

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
            LoginResult result = loginUseCase.execute(new LoginCommand(tenant.tenantId(), form.getEmail(), form.getPassword()));
            sessionEstablisher.establish(result, request, response);
            return "redirect:/account";
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
}
