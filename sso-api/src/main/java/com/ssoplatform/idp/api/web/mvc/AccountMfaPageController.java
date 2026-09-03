package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.application.exception.ApplicationException;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmEmailOtpEnrollmentCommand;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmEmailOtpEnrollmentResult;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmEmailOtpEnrollmentUseCase;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentCommand;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentResult;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentUseCase;
import com.ssoplatform.idp.application.usecase.mfa.DisableMfaCommand;
import com.ssoplatform.idp.application.usecase.mfa.DisableMfaUseCase;
import com.ssoplatform.idp.application.usecase.mfa.EnableEmailOtpCommand;
import com.ssoplatform.idp.application.usecase.mfa.EnableEmailOtpResult;
import com.ssoplatform.idp.application.usecase.mfa.EnableEmailOtpUseCase;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpCommand;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpResult;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpUseCase;
import com.ssoplatform.idp.application.usecase.mfa.GetMfaStatusQuery;
import com.ssoplatform.idp.application.usecase.mfa.GetMfaStatusResult;
import com.ssoplatform.idp.application.usecase.mfa.GetMfaStatusUseCase;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Server-rendered "manage my two-factor authentication" flow (Thymeleaf, Phase 4.1, extended Phase
 * 4.2), mirroring {@code AuthApiController}'s REST equivalent ({@code MfaApiController}) - both
 * call the exact same use cases, so behavior never diverges. Not in {@code SecurityConfig}'s
 * permitAll list: every mapping here requires an existing session, exactly like {@code
 * /account/change-password}.
 *
 * <p>All actions render back onto the single {@code account-mfa} template rather than redirecting,
 * so the TOTP enrollment secret and the recovery codes can be shown directly in the response that
 * produced them - redirecting first would lose that data (never persisted anywhere the next
 * request could re-read it, by design: a secret shown once, a recovery-code batch shown once).
 *
 * <p>Since a user may have at most one active second factor at a time (see {@code
 * EnableEmailOtpUseCase}/{@code EnrollTotpUseCase}), the steady-state view offers BOTH "enable
 * TOTP" and "enable e-mail OTP" only while neither is active or pending; once either is confirmed,
 * the view collapses to a single "disable" action regardless of which method is active.
 *
 * <p>A wrong confirmation code deliberately does NOT re-display the pending TOTP secret/e-mail OTP
 * address state in full: the credential is still {@code PENDING_ACTIVATION} in the database either
 * way, and starting enrollment again is cheap and idempotent (see {@code EnrollTotpUseCase}/{@code
 * EnableEmailOtpUseCase} - the latter also re-sends a fresh code), so the simplest correct recovery
 * from a mistake is to click "enable" again rather than plumbing that state through the error path.
 */
@Controller
public class AccountMfaPageController {

    private final GetMfaStatusUseCase getMfaStatusUseCase;
    private final EnrollTotpUseCase enrollTotpUseCase;
    private final ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase;
    private final EnableEmailOtpUseCase enableEmailOtpUseCase;
    private final ConfirmEmailOtpEnrollmentUseCase confirmEmailOtpEnrollmentUseCase;
    private final DisableMfaUseCase disableMfaUseCase;

    public AccountMfaPageController(
            GetMfaStatusUseCase getMfaStatusUseCase,
            EnrollTotpUseCase enrollTotpUseCase,
            ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase,
            EnableEmailOtpUseCase enableEmailOtpUseCase,
            ConfirmEmailOtpEnrollmentUseCase confirmEmailOtpEnrollmentUseCase,
            DisableMfaUseCase disableMfaUseCase) {
        this.getMfaStatusUseCase = getMfaStatusUseCase;
        this.enrollTotpUseCase = enrollTotpUseCase;
        this.confirmTotpEnrollmentUseCase = confirmTotpEnrollmentUseCase;
        this.enableEmailOtpUseCase = enableEmailOtpUseCase;
        this.confirmEmailOtpEnrollmentUseCase = confirmEmailOtpEnrollmentUseCase;
        this.disableMfaUseCase = disableMfaUseCase;
    }

    @GetMapping("/account/mfa")
    public String showMfaSettings(Model model, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        addStatus(model, principal);
        addForms(model);
        return "account-mfa";
    }

    @PostMapping("/account/mfa/totp/enroll")
    public String enrollTotp(Model model, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        addStatus(model, principal);
        addForms(model);
        try {
            EnrollTotpResult result = enrollTotpUseCase.execute(new EnrollTotpCommand(principal.userId()));
            model.addAttribute("pendingSecret", result.secretBase32());
            model.addAttribute("pendingOtpauthUri", result.otpauthUri());
        } catch (ApplicationException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
        }
        return "account-mfa";
    }

    @PostMapping("/account/mfa/totp/confirm")
    public String confirmTotp(
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

    @PostMapping("/account/mfa/email-otp/enable")
    public String enableEmailOtp(Model model, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        addStatus(model, principal);
        addForms(model);
        try {
            EnableEmailOtpResult result = enableEmailOtpUseCase.execute(new EnableEmailOtpCommand(principal.userId()));
            model.addAttribute("emailOtpPending", true);
            model.addAttribute("pendingEmailOtpMaskedEmail", result.maskedEmail());
        } catch (ApplicationException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
        }
        return "account-mfa";
    }

    @PostMapping("/account/mfa/email-otp/confirm")
    public String confirmEmailOtp(
            @ModelAttribute("emailOtpConfirmForm") MfaConfirmForm form,
            Model model,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        addStatus(model, principal);
        addForms(model);
        try {
            ConfirmEmailOtpEnrollmentResult result = confirmEmailOtpEnrollmentUseCase.execute(
                    new ConfirmEmailOtpEnrollmentCommand(principal.userId(), form.getCode()));
            model.addAttribute("recoveryCodes", result.recoveryCodes());
            model.addAttribute("mfaEnabled", true);
        } catch (ApplicationException ex) {
            model.addAttribute("errorMessage", ex.getMessage());
            // The pending credential survives a wrong code (see this class's Javadoc) - keep the
            // confirm form on screen for a genuine retry, without re-showing the masked address.
            model.addAttribute("emailOtpPending", true);
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
            GetMfaStatusResult status = getMfaStatusUseCase.execute(new GetMfaStatusQuery(principal.userId()));
            model.addAttribute("mfaEnabled", status.enabled());
            // Exposed as its plain name (not the enum itself) so the Thymeleaf template can
            // compare it to a string literal (${mfaMethod == 'EMAIL_OTP'}) unambiguously.
            model.addAttribute("mfaMethod", status.method() == null ? null : status.method().name());
        }
    }

    private void addForms(Model model) {
        if (!model.containsAttribute("confirmForm")) {
            model.addAttribute("confirmForm", new MfaConfirmForm());
        }
        if (!model.containsAttribute("emailOtpConfirmForm")) {
            model.addAttribute("emailOtpConfirmForm", new MfaConfirmForm());
        }
        if (!model.containsAttribute("disableForm")) {
            model.addAttribute("disableForm", new MfaDisableForm());
        }
    }
}
