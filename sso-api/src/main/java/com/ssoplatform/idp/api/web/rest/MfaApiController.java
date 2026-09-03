package com.ssoplatform.idp.api.web.rest;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentCommand;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentResult;
import com.ssoplatform.idp.application.usecase.mfa.ConfirmTotpEnrollmentUseCase;
import com.ssoplatform.idp.application.usecase.mfa.DisableMfaCommand;
import com.ssoplatform.idp.application.usecase.mfa.DisableMfaUseCase;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpCommand;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpResult;
import com.ssoplatform.idp.application.usecase.mfa.EnrollTotpUseCase;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaRecoveryCodeChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaRecoveryCodeChallengeUseCase;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaTotpChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaTotpChallengeUseCase;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API for TOTP-based MFA (Phase 4.1). Two different authentication shapes coexist here,
 * exactly as {@code SecurityConfig}'s authorization rules distinguish them:
 *
 * <ul>
 *   <li>{@code /totp/enroll}, {@code /totp/confirm}, {@code /disable} require an EXISTING Spring
 *       Security session ({@code @AuthenticationPrincipal}) - a user manages their own MFA
 *       settings only once already logged in, exactly like {@code /api/account/change-password}.
 *   <li>{@code /challenge/totp}, {@code /challenge/recovery-code} require NO session at all - they
 *       are the second step of login itself, identified purely by the opaque {@code
 *       challengeToken} {@code POST /api/login} returned, exactly like {@code /api/login} needs
 *       none either. A successful call to either establishes the session, via the same {@link
 *       AuthenticatedSessionEstablisher} {@code /api/login} uses for {@code
 *       LoginOutcome.Authenticated}.
 * </ul>
 */
@RestController
@RequestMapping("/api/mfa")
public class MfaApiController {

    private final EnrollTotpUseCase enrollTotpUseCase;
    private final ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase;
    private final DisableMfaUseCase disableMfaUseCase;
    private final VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase;
    private final VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;

    public MfaApiController(
            EnrollTotpUseCase enrollTotpUseCase,
            ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase,
            DisableMfaUseCase disableMfaUseCase,
            VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase,
            VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase,
            AuthenticatedSessionEstablisher sessionEstablisher) {
        this.enrollTotpUseCase = enrollTotpUseCase;
        this.confirmTotpEnrollmentUseCase = confirmTotpEnrollmentUseCase;
        this.disableMfaUseCase = disableMfaUseCase;
        this.verifyMfaTotpChallengeUseCase = verifyMfaTotpChallengeUseCase;
        this.verifyMfaRecoveryCodeChallengeUseCase = verifyMfaRecoveryCodeChallengeUseCase;
        this.sessionEstablisher = sessionEstablisher;
    }

    @PostMapping("/totp/enroll")
    public MfaEnrollResponse enroll(@AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        EnrollTotpResult result = enrollTotpUseCase.execute(new EnrollTotpCommand(principal.userId()));
        return new MfaEnrollResponse(result.secretBase32(), result.otpauthUri());
    }

    @PostMapping("/totp/confirm")
    public MfaConfirmResponse confirm(
            @RequestBody MfaConfirmRequest request, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        ConfirmTotpEnrollmentResult result = confirmTotpEnrollmentUseCase.execute(
                new ConfirmTotpEnrollmentCommand(principal.userId(), request.code()));
        return new MfaConfirmResponse(result.recoveryCodes());
    }

    @PostMapping("/disable")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void disable(
            @RequestBody MfaDisableRequest request, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        disableMfaUseCase.execute(new DisableMfaCommand(principal.userId(), request.currentPassword()));
    }

    @PostMapping("/challenge/totp")
    public LoginResponse challengeWithTotp(
            @RequestBody MfaTotpChallengeRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse) {
        LoginResult result = verifyMfaTotpChallengeUseCase.execute(
                new VerifyMfaTotpChallengeCommand(request.challengeToken(), request.code()));
        sessionEstablisher.establish(result, servletRequest, servletResponse);
        return LoginResponse.authenticated(result.userId(), result.email());
    }

    @PostMapping("/challenge/recovery-code")
    public LoginResponse challengeWithRecoveryCode(
            @RequestBody MfaRecoveryCodeChallengeRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse) {
        LoginResult result = verifyMfaRecoveryCodeChallengeUseCase.execute(
                new VerifyMfaRecoveryCodeChallengeCommand(request.challengeToken(), request.recoveryCode()));
        sessionEstablisher.establish(result, servletRequest, servletResponse);
        return LoginResponse.authenticated(result.userId(), result.email());
    }
}
