package com.ssoplatform.idp.api.web.rest;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
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
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaEmailOtpChallengeCommand;
import com.ssoplatform.idp.application.usecase.mfa.VerifyMfaEmailOtpChallengeUseCase;
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
 * REST API for MFA: TOTP (Phase 4.1) and e-mail OTP (Phase 4.2), a second, alternative method a
 * user may enable instead (never both at once - see {@code EnableEmailOtpUseCase}/{@code
 * EnrollTotpUseCase}). Two different authentication shapes coexist here, exactly as {@code
 * SecurityConfig}'s authorization rules distinguish them:
 *
 * <ul>
 *   <li>{@code /totp/enroll}, {@code /totp/confirm}, {@code /email-otp/enable}, {@code
 *       /email-otp/confirm}, and {@code /disable} require an EXISTING Spring Security session
 *       ({@code @AuthenticationPrincipal}) - a user manages their own MFA settings only once
 *       already logged in, exactly like {@code /api/account/change-password}.
 *   <li>{@code /challenge/totp}, {@code /challenge/email-otp}, {@code /challenge/recovery-code}
 *       require NO session at all - they are the second step of login itself, identified purely
 *       by the opaque {@code challengeToken} {@code POST /api/login} returned, exactly like {@code
 *       /api/login} needs none either. A successful call to any of them establishes the session,
 *       via the same {@link AuthenticatedSessionEstablisher} {@code /api/login} uses for {@code
 *       LoginOutcome.Authenticated}.
 * </ul>
 *
 * <p>{@code /disable} deliberately serves BOTH methods through one endpoint - see {@code
 * DisableMfaUseCase}'s Javadoc for why disabling "my second factor" is one capability regardless
 * of which method is active.
 */
@RestController
@RequestMapping("/api/mfa")
public class MfaApiController {

    private final EnrollTotpUseCase enrollTotpUseCase;
    private final ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase;
    private final EnableEmailOtpUseCase enableEmailOtpUseCase;
    private final ConfirmEmailOtpEnrollmentUseCase confirmEmailOtpEnrollmentUseCase;
    private final DisableMfaUseCase disableMfaUseCase;
    private final VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase;
    private final VerifyMfaEmailOtpChallengeUseCase verifyMfaEmailOtpChallengeUseCase;
    private final VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;

    public MfaApiController(
            EnrollTotpUseCase enrollTotpUseCase,
            ConfirmTotpEnrollmentUseCase confirmTotpEnrollmentUseCase,
            EnableEmailOtpUseCase enableEmailOtpUseCase,
            ConfirmEmailOtpEnrollmentUseCase confirmEmailOtpEnrollmentUseCase,
            DisableMfaUseCase disableMfaUseCase,
            VerifyMfaTotpChallengeUseCase verifyMfaTotpChallengeUseCase,
            VerifyMfaEmailOtpChallengeUseCase verifyMfaEmailOtpChallengeUseCase,
            VerifyMfaRecoveryCodeChallengeUseCase verifyMfaRecoveryCodeChallengeUseCase,
            AuthenticatedSessionEstablisher sessionEstablisher) {
        this.enrollTotpUseCase = enrollTotpUseCase;
        this.confirmTotpEnrollmentUseCase = confirmTotpEnrollmentUseCase;
        this.enableEmailOtpUseCase = enableEmailOtpUseCase;
        this.confirmEmailOtpEnrollmentUseCase = confirmEmailOtpEnrollmentUseCase;
        this.disableMfaUseCase = disableMfaUseCase;
        this.verifyMfaTotpChallengeUseCase = verifyMfaTotpChallengeUseCase;
        this.verifyMfaEmailOtpChallengeUseCase = verifyMfaEmailOtpChallengeUseCase;
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

    @PostMapping("/email-otp/enable")
    public EmailOtpEnableResponse enableEmailOtp(@AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        EnableEmailOtpResult result = enableEmailOtpUseCase.execute(new EnableEmailOtpCommand(principal.userId()));
        return new EmailOtpEnableResponse(result.maskedEmail());
    }

    @PostMapping("/email-otp/confirm")
    public MfaConfirmResponse confirmEmailOtp(
            @RequestBody MfaConfirmRequest request, @AuthenticationPrincipal SsoAuthenticatedPrincipal principal) {
        ConfirmEmailOtpEnrollmentResult result = confirmEmailOtpEnrollmentUseCase.execute(
                new ConfirmEmailOtpEnrollmentCommand(principal.userId(), request.code()));
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

    @PostMapping("/challenge/email-otp")
    public LoginResponse challengeWithEmailOtp(
            @RequestBody MfaEmailOtpChallengeRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse) {
        LoginResult result = verifyMfaEmailOtpChallengeUseCase.execute(
                new VerifyMfaEmailOtpChallengeCommand(request.challengeToken(), request.code()));
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
