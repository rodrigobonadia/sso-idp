package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.application.exception.IncorrectCurrentPasswordException;
import com.ssoplatform.idp.application.usecase.user.ChangePasswordCommand;
import com.ssoplatform.idp.application.usecase.user.ChangePasswordUseCase;
import com.ssoplatform.idp.domain.shared.DomainException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Server-rendered "change my password" flow (Thymeleaf), for an already-authenticated user who
 * knows their current password - as opposed to {@code ForgotPasswordPageController}'s unauthenticated,
 * e-mail-token-based reset. Not in {@code SecurityConfig}'s permitAll list, so both endpoints here
 * require an existing session, exactly like {@code GET /account}.
 */
@Controller
public class ChangePasswordPageController {

    private final ChangePasswordUseCase changePasswordUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;

    public ChangePasswordPageController(
            ChangePasswordUseCase changePasswordUseCase, AuthenticatedSessionEstablisher sessionEstablisher) {
        this.changePasswordUseCase = changePasswordUseCase;
        this.sessionEstablisher = sessionEstablisher;
    }

    @GetMapping("/account/change-password")
    public String showChangePasswordForm(Model model) {
        if (!model.containsAttribute("changePasswordForm")) {
            model.addAttribute("changePasswordForm", new ChangePasswordForm());
        }
        return "change-password";
    }

    @PostMapping("/account/change-password")
    public String submitChangePassword(
            @ModelAttribute("changePasswordForm") ChangePasswordForm form,
            Model model,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal,
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            changePasswordUseCase.execute(
                    new ChangePasswordCommand(principal.userId(), form.getCurrentPassword(), form.getNewPassword()));
            // The session that just proved the OLD password is no longer trustworthy once a new
            // one is set - require signing in again, exactly like a "forgot password" reset does.
            sessionEstablisher.invalidateCurrentSession(request, response);
            return "redirect:/login?password-changed";
        } catch (IncorrectCurrentPasswordException | DomainException ex) {
            // Covers WeakPasswordException: user-facing change-password failures belong back on
            // the form, not a generic error page.
            model.addAttribute("errorMessage", ex.getMessage());
            return "change-password";
        }
    }
}
