package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.application.exception.ApplicationException;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentCommand;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentResult;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentUseCase;
import com.ssoplatform.idp.application.usecase.mfa.DisableMfaCommand;
import com.ssoplatform.idp.application.usecase.mfa.DisableMfaUseCase;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpCommand;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpResult;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpUseCase;
import com.ssoplatform.idp.application.usecase.mfa.GetMfaStatusQuery;
import com.ssoplatform.idp.application.usecase.mfa.GetMfaStatusUseCase;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Server-rendered "manage my two-factor authentication" flow (Thymeleaf), mirroring {@code
 * AuthApiController}'s REST equivalent ({@code MfaApiController}) - both call the exact same use
 * cases, so behavior never diverges. Not in {@code SecurityConfig}'s permitAll list: every mapping
 * here requires an existing session, exactly like {@code /account/change-password}.
 *
 * <p>All three actions render back onto the single {@code account-mfa} template rather than
 * redirecting, so the enrollment secret and the recovery codes can be shown directly in the
 * response that produced them - redirecting first would lose that data (it is never persisted
 * anywhere the next request could re-read it, by design: a secret shown once, a recovery-code
 * batch shown once).
 *
 * <p>A wrong confirmation code deliberately does NOT re-display the pending secret/QR: the
 * credential is still {@code PENDING_ACTIVATION} in the database either way, and starting
 * enrollment again is cheap and idempotent (see {@code EnrollTotpUseCase}), so the simplest correct
 * recovery from a mistake is to click "enable" again rather than plumbing the secret through the
 * error path.
 */
@Controller
public class AccountMfaPageController {

    private final GetMfaStatusUseCase getMfaStatusUseCase;
    private final EnrollTotpUseCase enrollTotpUseCase;
    private final ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase;
    private final DisableMfaUseCase disableMfaUseCase;

    public AccountMfaPageController(
            GetMfaStatusUseCase getMfaStatusUseCase,
            EnrollTotpUseCase enrollTotpUseCase,
            ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase,
            DisableMfaUseCase disableMfaUseCase) {
        this.getMfaStatusUseCase = getMfaStatusUseCase;
        this.enrollTotpUseCase = enrollTotpUseCase;
        this.confirmTotpEnrollmentUseCase = confirmTotpEnrollmentUseCase;
        this.disableMfaUseCase = disableMfaUseCase;
    }

    @GetMapping("/account/mfa")
    public String showMfaSettings(Model model, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        addStatus(model, principal);
        addForms(model);
        return "account-mfa";
    }

    @PostMapping("/account/mfa/enroll")
    public String enroll(Model model, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        EnrollTotpResult result = enrollTotpUseCase.execute(new EnrollTotpCommand(principal.userId()));
        addStatus(model, principal);
        addForms(model);
        model.addAttribute("pendingSecret", result.secretBase32());
        model.addAttribute("pendingOtpauthUri", result.otpauthUri());
        return "account-mfa";
    }

    @PostMapping("/account/mfa/confirm")
    public String confirm(
            @ModelAttribute("confirmForm") MfaConfirmForm form,
            Model model,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        addStatus(model, principal);
        addForms(model);
        try {
            ConfirmTotpEnrollmentResult result = confirmTotpEnrollmentUseCase.execute(
                    new ConfirmTotpEnrollmentCommand(principal.userId(), form.getCode()));
            model.addAttribute("recoveryCodes", result.recoveryCodes());
            model.addAttribute("mfaEnabled", true);
        } catch (ApplicationException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
        }
        return "account-mfa";
    }

    @PostMapping("/account/mfa/disable")
    public String disable(
            @ModelAttribute("disableForm") MfaDisableForm form,
            Model model,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        try {
            disableMfaUseCase.execute(new DisableMfaCommand(principal.userId(), form.getCurrentPassword()));
        } catch (ApplicationException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
        }
        addStatus(model, principal);
        addForms(model);
        return "account-mfa";
    }

    private void addStatus(Model model, SsoAuthenticatedPrincipal principal) {
        if (!model.containsAttribute("mfaEnabled")) {
            boolean enabled = getMfaStatusUseCase.execute(new GetMfaStatusQuery(principal.userId())).enabled();
            model.addAttribute("mfaEnabled", enabled);
        }
    }

    private void addForms(Model model) {
        if (!model.containsAttribute("confirmForm")) {
            model.addAttribute("confirmForm", new MfaConfirmForm());
        }
        if (!model.containsAttribute("disableForm")) {
            model.addAttribute("disableForm", new MfaDisableForm());
        }
    }
}
