package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.DuplicateEmailException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.user.RegisterUserCommand;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailCommand;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailResult;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailUseCase;
import com.ssoplatform.idp.application.usecase.user.RegisterUserUseCase;
import com.ssoplatform.idp.domain.shared.DomainException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Server-rendered registration flow (Thymeleaf), for tenants who want to use the platform's own
 * screens rather than build their own on top of the REST API in {@code web.rest}. Both surfaces
 * are thin adapters over the exact same use cases.
 */
@Controller
public class RegistrationPageController {

    private final RegisterUserUseCase registerUserUseCase;
    private final VerifyEmailUseCase verifyEmailUseCase;
    private final TenantContext tenantContext;

    public RegistrationPageController(
            RegisterUserUseCase registerUserUseCase, VerifyEmailUseCase verifyEmailUseCase, TenantContext tenantContext) {
        this.registerUserUseCase = registerUserUseCase;
        this.verifyEmailUseCase = verifyEmailUseCase;
        this.tenantContext = tenantContext;
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        requireTenant();
        if (!model.containsAttribute("registrationForm")) {
            model.addAttribute("registrationForm", new RegistrationForm());
        }
        return "register";
    }

    @PostMapping("/register")
    public String submitRegistration(@ModelAttribute("registrationForm") RegistrationForm form, Model model) {
        TenantSummary tenant = requireTenant();
        try {
            registerUserUseCase.execute(
                    new RegisterUserCommand(tenant.tenantId(), tenant.slug(), form.getEmail(), form.getPassword()));
            return "redirect:/register/check-email";
        } catch (DuplicateEmailException | DomainException ex) {
            // DomainException covers WeakPasswordException/InvalidEmailException: user-input
            // problems that belong back on the form, not a generic error page.
            model.addAttribute("errorMessage", ex.getMessage());
            return "register";
        }
    }

    @GetMapping("/register/check-email")
    public String showCheckEmailNotice() {
        requireTenant();
        return "check-email";
    }

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam("token") String token, Model model) {
        try {
            VerifyEmailResult result = verifyEmailUseCase.execute(new VerifyEmailCommand(token));
            model.addAttribute("success", true);
            model.addAttribute("email", result.email());
        } catch (RuntimeException ex) {
            model.addAttribute("success", false);
            model.addAttribute("errorMessage", ex.getMessage());
        }
        return "verify-email-result";
    }

    private TenantSummary requireTenant() {
        return tenantContext.tenant().orElseThrow(TenantRequiredException::new);
    }
}
