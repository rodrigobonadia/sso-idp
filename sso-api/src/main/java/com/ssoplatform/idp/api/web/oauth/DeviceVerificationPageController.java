package com.ssoplatform.idp.api.web.oauth;

import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.DeviceAuthorizationNotFoundException;
import com.ssoplatform.idp.application.usecase.device.DecideDeviceAuthorizationCommand;
import com.ssoplatform.idp.application.usecase.device.DecideDeviceAuthorizationUseCase;
import com.ssoplatform.idp.application.usecase.device.DeviceAuthorizationDecision;
import com.ssoplatform.idp.application.usecase.device.DeviceAuthorizationView;
import com.ssoplatform.idp.application.usecase.device.FindDeviceAuthorizationCommand;
import com.ssoplatform.idp.application.usecase.device.FindDeviceAuthorizationUseCase;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The human-facing side of the Device Authorization Grant (RFC 8628 §3.3): a user visits {@code
 * GET /device} (typically from {@code verification_uri_complete}, with {@code user_code}
 * pre-filled - see {@code RequestDeviceAuthorizationResult}), confirms the code, and clicks Allow
 * or Deny for the device that requested it.
 *
 * <p>Requires an authenticated session, exactly like {@code /authorize} - an unauthenticated
 * {@code GET /device} redirects to {@code /login} and resumes back here afterward (see {@code
 * SecurityConfig}'s Javadoc for why only the GET mapping is covered by that entry point, never the
 * POSTs below). There is no consent screen here either, consistent with {@code AuthorizeUseCase}:
 * {@link DeviceAuthorizationView} carries only the requesting client's display name, never a scope
 * list, and the confirmation page's only choice is Allow/Deny for the WHOLE request - mirroring how
 * real IdPs (e.g. GitHub CLI's device login) present this step.
 *
 * <p>{@code POST /device} (submitting the typed {@code user_code}) and {@code POST
 * /device/allow}/{@code /device/deny} (the actual decision) are three separate steps, not one, so
 * that a user who mistypes the code sees an error on the SAME simple form rather than a decision
 * screen for the wrong device - and so that {@code DecideDeviceAuthorizationUseCase} always
 * re-resolves the code from {@code user_code} rather than trusting an internal id carried through
 * a hidden form field untouched (see that use case's Javadoc).
 */
@Controller
public class DeviceVerificationPageController {

    private final FindDeviceAuthorizationUseCase findDeviceAuthorizationUseCase;
    private final DecideDeviceAuthorizationUseCase decideDeviceAuthorizationUseCase;
    private final TenantContext tenantContext;

    public DeviceVerificationPageController(
            FindDeviceAuthorizationUseCase findDeviceAuthorizationUseCase,
            DecideDeviceAuthorizationUseCase decideDeviceAuthorizationUseCase,
            TenantContext tenantContext) {
        this.findDeviceAuthorizationUseCase = findDeviceAuthorizationUseCase;
        this.decideDeviceAuthorizationUseCase = decideDeviceAuthorizationUseCase;
        this.tenantContext = tenantContext;
    }

    @GetMapping("/device")
    public String showForm(@RequestParam(value = "user_code", required = false) String userCode, Model model) {
        requireTenant();
        if (!model.containsAttribute("userCode")) {
            model.addAttribute("userCode", userCode == null ? "" : userCode);
        }
        return "device";
    }

    @PostMapping("/device")
    public String submitUserCode(@RequestParam("user_code") String userCode, Model model) {
        TenantSummary tenant = requireTenant();
        try {
            DeviceAuthorizationView view = findDeviceAuthorizationUseCase.execute(
                    new FindDeviceAuthorizationCommand(tenant.tenantId(), userCode));
            model.addAttribute("userCode", view.userCode());
            model.addAttribute("clientName", view.clientName());
            return "device-confirm";
        } catch (DeviceAuthorizationNotFoundException ex) {
            model.addAttribute("userCode", userCode);
            model.addAttribute("errorMessage", ex.getMessage());
            return "device";
        }
    }

    @PostMapping("/device/allow")
    public String allow(
            @RequestParam("user_code") String userCode,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal,
            Model model) {
        return decide(userCode, principal, DeviceAuthorizationDecision.ALLOW, model);
    }

    @PostMapping("/device/deny")
    public String deny(
            @RequestParam("user_code") String userCode,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal,
            Model model) {
        return decide(userCode, principal, DeviceAuthorizationDecision.DENY, model);
    }

    private String decide(
            String userCode, SsoAuthenticatedPrincipal principal, DeviceAuthorizationDecision decision, Model model) {
        TenantSummary tenant = requireTenant();
        try {
            decideDeviceAuthorizationUseCase.execute(new DecideDeviceAuthorizationCommand(
                    tenant.tenantId(), principal.userId(), userCode, decision));
            model.addAttribute("approved", decision == DeviceAuthorizationDecision.ALLOW);
            return "device-result";
        } catch (DeviceAuthorizationNotFoundException ex) {
            model.addAttribute("userCode", "");
            model.addAttribute("errorMessage", ex.getMessage());
            return "device";
        }
    }

    private TenantSummary requireTenant() {
        return tenantContext.tenant().orElseThrow(TenantRequiredException::new);
    }
}
