package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.application.exception.ApplicationException;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaEmailOtpChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaEmailOtpChallengeUseCase;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaRecoveryCodeChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaRecoveryCodeChallengeUseCase;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaTotpChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaTotpChallengeUseCase;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.domain.mfa.MfaMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * Server-rendered second step of a two-step login (Phase 4.1, extended Phase 4.2): shown only
 * after {@link LoginPageController#submitLogin} received {@code LoginOutcome.MfaChallengeIssued}
 * instead of establishing a session directly.
 *
 * <p>Both the challenge token AND, since Phase 4.2, the method it was issued for are kept entirely
 * server-side, in the {@code HttpSession} under {@link #CHALLENGE_TOKEN_SESSION_ATTRIBUTE}/{@link
 * #MFA_METHOD_SESSION_ATTRIBUTE} - deliberately never placed in a URL query parameter, which would
 * leak them via browser history and the {@code Referer} header. A request to either mapping with
 * no such session attribute (the user navigated here directly, or the challenge was already
 * consumed/expired and the session attributes cleared) simply bounces back to {@code /login} -
 * there is nothing to challenge.
 *
 * <p>Accepts either a primary-method code or a recovery code in the same form ({@link
 * MfaChallengeForm}): a non-blank {@code recoveryCode} always wins (checked first, regardless of
 * method - a recovery code is always a valid fallback for either method), otherwise {@code code}
 * is checked against whichever use case matches the session's stored method. On success, clears
 * both session attributes and establishes the session exactly like {@link LoginPageController}
 * does, including resuming a saved {@code /authorize} (or {@code /device}) request the same way.
 */
@Controller
public class MfaChallengePageController {

    static final String CHALLENGE_TOKEN_SESSION_ATTRIBUTE = "mfaChallengeToken";
    static final String MFA_METHOD_SESSION_ATTRIBUTE = "mfaChallengeMethod";

    private final VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase;
    private final VerifyMfaEmailOtpChallengeUseCase verifyMfaEmailOtpChallengeUseCase;
    private final VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public MfaChallengePageController(
            VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase,
            VerifyMfaEmailOtpChallengeUseCase verifyMfaEmailOtpChallengeUseCase,
            VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase,
            AuthenticatedSessionEstablisher sessionEstablisher) {
        this.verifyMfaTotpChallengeUseCase = verifyMfaTotpChallengeUseCase;
        this.verifyMfaEmailOtpChallengeUseCase = verifyMfaEmailOtpChallengeUseCase;
        this.verifyMfaRecoveryCodeChallengeUseCase = verifyMfaRecoveryCodeChallengeUseCase;
        this.sessionEstablisher = sessionEstablisher;
    }

    @GetMapping("/login/mfa")
    public String showChallengeForm(HttpSession session, Model model) {
        if (session.getAttribute(CHALLENGE_TOKEN_SESSION_ATTRIBUTE) == null) {
            return "redirect:/login";
        }
        if (!model.containsAttribute("challengeForm")) {
            model.addAttribute("challengeForm", new MfaChallengeForm());
        }
        model.addAttribute("mfaMethod", session.getAttribute(MFA_METHOD_SESSION_ATTRIBUTE));
        return "mfa-challenge";
    }

    @PostMapping("/login/mfa")
    public String submitChallenge(
            @ModelAttribute("challengeForm") MfaChallengeForm form,
            HttpSession session,
            Model model,
            HttpServletRequest request,
            HttpServletResponse response) {
        String challengeToken = (String) session.getAttribute(CHALLENGE_TOKEN_SESSION_ATTRIBUTE);
        String method = (String) session.getAttribute(MFA_METHOD_SESSION_ATTRIBUTE);
        if (challengeToken == null) {
            return "redirect:/login";
        }
        try {
            LoginResult result = resolveResult(form, challengeToken, method);
            session.removeAttribute(CHALLENGE_TOKEN_SESSION_ATTRIBUTE);
            session.removeAttribute(MFA_METHOD_SESSION_ATTRIBUTE);
            sessionEstablisher.establish(result, request, response);
            return "redirect:" + resolvePostLoginRedirect(request, response);
        } catch (ApplicationException ex) {
            // Covers InvalidMfaCodeException/VerificationTokenExpiredException/
            // VerificationTokenAlreadyConsumedException/VerificationTokenNotFoundException/
            // TooManyFailedEmailOtpAttemptsException: all user-facing challenge failures belong
            // back on the form.
            model.addAttribute("errorMessage", ex.getMessage());
            model.addAttribute("mfaMethod", method);
            return "mfa-challenge";
        }
    }

    private LoginResult resolveResult(MfaChallengeForm form, String challengeToken, String method) {
        if (!isBlank(form.getRecoveryCode())) {
            return verifyMfaRecoveryCodeChallengeUseCase.execute(
                    new VerifyMfaRecoveryCodeChallengeCommand(challengeToken, form.getRecoveryCode()));
        }
        if (MfaMethod.EMAIL_OTP.name().equals(method)) {
            return verifyMfaEmailOtpChallengeUseCase.execute(
                    new VerifyMfaEmailOtpChallengeCommand(challengeToken, form.getCode()));
        }
        return verifyMfaTotpChallengeUseCase.execute(
                new VerifyMfaTotpChallengeCommand(challengeToken, form.getCode()));
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** Mirrors {@link LoginPageController#resolvePostLoginRedirect} exactly - see its Javadoc. */
    private String resolvePostLoginRedirect(HttpServletRequest request, HttpServletResponse response) {
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest == null) {
            return "/account";
        }
        requestCache.removeRequest(request, response);
        return savedRequest.getRedirectUrl();
    }
}
