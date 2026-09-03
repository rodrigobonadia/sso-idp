package com.ssoplatform.idp.api.web.mvc;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.application.exception.ApplicationException;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaRecoveryCodeChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaRecoveryCodeChallengeUseCase;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaTotpChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaTotpChallengeUseCase;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
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
 * Server-rendered second step of a two-step login (Phase 4.1): shown only after {@link
 * LoginPageController#submitLogin} received {@code LoginOutcome.MfaChallengeIssued} instead of
 * establishing a session directly.
 *
 * <p>The challenge token is kept entirely server-side, in the {@code HttpSession} under {@link
 * #CHALLENGE_TOKEN_SESSION_ATTRIBUTE} - deliberately never placed in a URL query parameter, which
 * would leak it via browser history and the {@code Referer} header. A request to either mapping
 * with no such session attribute (the user navigated here directly, or the challenge was already
 * consumed/expired and the session attribute cleared) simply bounces back to {@code /login} -
 * there is nothing to challenge.
 *
 * <p>Accepts either a TOTP code or a recovery code in the same form ({@link MfaChallengeForm}):
 * whichever field is non-blank determines which use case runs. On success, clears the session
 * attribute and establishes the session exactly like {@link LoginPageController} does, including
 * resuming a saved {@code /authorize} (or {@code /device}) request the same way.
 */
@Controller
public class MfaChallengePageController {

    static final String CHALLENGE_TOKEN_SESSION_ATTRIBUTE = "mfaChallengeToken";

    private final VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase;
    private final VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;
    private final RequestCache requestCache = new HttpSessionRequestCache();

    public MfaChallengePageController(
            VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase,
            VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase,
            AuthenticatedSessionEstablisher sessionEstablisher) {
        this.verifyMfaTotpChallengeUseCase = verifyMfaTotpChallengeUseCase;
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
        if (challengeToken == null) {
            return "redirect:/login";
        }
        try {
            LoginResult result = isBlank(form.getRecoveryCode())
                    ? verifyMfaTotpChallengeUseCase.execute(
                            new VerifyMfaTotpChallengeCommand(challengeToken, form.getCode()))
                    : verifyMfaRecoveryCodeChallengeUseCase.execute(
                            new VerifyMfaRecoveryCodeChallengeCommand(challengeToken, form.getRecoveryCode()));
            session.removeAttribute(CHALLENGE_TOKEN_SESSION_ATTRIBUTE);
            sessionEstablisher.establish(result, request, response);
            return "redirect:" + resolvePostLoginRedirect(request, response);
        } catch (ApplicationException ex) {
            // Covers InvalidMfaCodeException/VerificationTokenExpiredException/
            // VerificationTokenAlreadyConsumedException/VerificationTokenNotFoundException/
            // MfaNotEnabledException: all user-facing challenge failures belong back on the form.
            model.addAttribute("errorMessage", ex.getMessage());
            return "mfa-challenge";
        }
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
