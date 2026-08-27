package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.user.RequestPasswordResetCommand;
import com.ssoplatform.idp.application.usecase.user.RequestPasswordResetUseCase;
import com.ssoplatform.idp.application.usecase.user.ResetPasswordCommand;
import com.ssoplatform.idp.application.usecase.user.ResetPasswordUseCase;
import com.ssoplatform.idp.domain.shared.DomainException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Server-rendered "forgot my password" flow (Thymeleaf): request a reset link by e-mail, then set
 * a new password from the link. See {@code AuthApiController} for the REST equivalent - both call
 * the exact same use cases.
 *
 * <p>{@code POST /forgot-password} always redirects to the same check-e-mail notice regardless of
 * whether the address matched an account - {@link RequestPasswordResetUseCase} is deliberately
 * enumeration-safe, and this controller must not undo that by branching on its outcome.
 *
 * <p>{@code POST /reset-password} invalidates whatever session THAT request happens to be
 * carrying (see {@link AuthenticatedSessionEstablisher#invalidateCurrentSession}'s Javadoc for
 * the scope limitation this implies): since resetting a password is by design something a caller
 * can do without being logged in, that request usually carries no session at all, or a different
 * one than any stale login the user still has open elsewhere - this deliberately does not reach
 * across devices/browsers to close every session for the user.
 */
@Controller
public class ForgotPasswordPageController {

    private final RequestPasswordResetUseCase requestPasswordResetUseCase;
    private final ResetPasswordUseCase resetPasswordUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;
    private final TenantContext tenantContext;

    public ForgotPasswordPageController(
            RequestPasswordResetUseCase requestPasswordResetUseCase,
            ResetPasswordUseCase resetPasswordUseCase,
            AuthenticatedSessionEstablisher sessionEstablisher,
            TenantContext tenantContext) {
        this.requestPasswordResetUseCase = requestPasswordResetUseCase;
        this.resetPasswordUseCase = resetPasswordUseCase;
        this.sessionEstablisher = sessionEstablisher;
        this.tenantContext = tenantContext;
    }

    @GetMapping("/forgot-password")
    public String showForgotPasswordForm(Model model) {
        requireTenant();
        if (!model.containsAttribute("forgotPasswordForm")) {
            model.addAttribute("forgotPasswordForm", new ForgotPasswordForm());
        }
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String submitForgotPassword(@ModelAttribute("forgotPasswordForm") ForgotPasswordForm form) {
        TenantSummary tenant = requireTenant();
        requestPasswordResetUseCase.execute(
                new RequestPasswordResetCommand(tenant.tenantId(), tenant.slug(), form.getEmail()));
        return "redirect:/forgot-password/check-email";
    }

    @GetMapping("/forgot-password/check-email")
    public String showCheckEmailNotice() {
        requireTenant();
        return "forgot-password-check-email";
    }

    @GetMapping("/reset-password")
    public String showResetPasswordForm(@RequestParam("token") String token, Model model) {
        if (!model.containsAttribute("resetPasswordForm")) {
            ResetPasswordForm form = new ResetPasswordForm();
            form.setToken(token);
            model.addAttribute("resetPasswordForm", form);
        }
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String submitResetPassword(
            @ModelAttribute("resetPasswordForm") ResetPasswordForm form,
            Model model,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            resetPasswordUseCase.execute(new ResetPasswordCommand(form.getToken(), form.getNewPassword()));
            // Invalidates only whatever session THIS request happens to be carrying (usually
            // none, or a different one than any stale login elsewhere) - see the class Javadoc
            // and AuthenticatedSessionEstablisher#invalidateCurrentSession for the scope
            // limitation: this does not reach across other devices/browsers.
            sessionEstablisher.invalidateCurrentSession(request, response);
            return "redirect:/login?password-reset";
        } catch (VerificationTokenNotFoundException | DomainException ex) {
            // Covers VerificationTokenAlreadyConsumedException/VerificationTokenExpiredException/
            // InvalidVerificationTokenException/WeakPasswordException/UserStateException: all
            // user-facing reset failures belong back on the form, not a generic error page.
            model.addAttribute("errorMessage", ex.getMessage());
            return "reset-password";
        }
    }

    private TenantSummary requireTenant() {
        return tenantContext.tenant().orElseThrow(TenantRequiredException::new);
    }
}
