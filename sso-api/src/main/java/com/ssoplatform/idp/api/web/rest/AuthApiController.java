package com.ssoplatform.idp.api.web.rest;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.security.SsoAuthenticatedPrincipal;
import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.user.ChangePasswordCommand;
import com.ssoplatform.idp.application.usecase.user.ChangePasswordResult;
import com.ssoplatform.idp.application.usecase.user.ChangePasswordUseCase;
import com.ssoplatform.idp.application.usecase.user.LoginCommand;
import com.ssoplatform.idp.application.usecase.user.LoginOutcome;
import com.ssoplatform.idp.application.usecase.user.LoginUseCase;
import com.ssoplatform.idp.application.usecase.user.RegisterUserCommand;
import com.ssoplatform.idp.application.usecase.user.RegisterUserResult;
import com.ssoplatform.idp.application.usecase.user.RegisterUserUseCase;
import com.ssoplatform.idp.application.usecase.user.RequestPasswordResetCommand;
import com.ssoplatform.idp.application.usecase.user.RequestPasswordResetUseCase;
import com.ssoplatform.idp.application.usecase.user.ResetPasswordCommand;
import com.ssoplatform.idp.application.usecase.user.ResetPasswordResult;
import com.ssoplatform.idp.application.usecase.user.ResetPasswordUseCase;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailCommand;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailResult;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailUseCase;
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
 * REST API for the native-registration and login flows, for callers building their own front-end
 * instead of using the server-rendered pages under {@code web.mvc}. Both surfaces sit on top of
 * the exact same use cases, so behavior never diverges between them - {@code /api/login}
 * establishes the exact same kind of session as the Thymeleaf {@code POST /login}, via the shared
 * {@link AuthenticatedSessionEstablisher}.
 */
@RestController
@RequestMapping("/api")
public class AuthApiController {

    private final RegisterUserUseCase registerUserUseCase;
    private final VerifyEmailUseCase verifyEmailUseCase;
    private final LoginUseCase loginUseCase;
    private final RequestPasswordResetUseCase requestPasswordResetUseCase;
    private final ResetPasswordUseCase resetPasswordUseCase;
    private final ChangePasswordUseCase changePasswordUseCase;
    private final AuthenticatedSessionEstablisher sessionEstablisher;
    private final TenantContext tenantContext;

    public AuthApiController(
            RegisterUserUseCase registerUserUseCase,
            VerifyEmailUseCase verifyEmailUseCase,
            LoginUseCase loginUseCase,
            RequestPasswordResetUseCase requestPasswordResetUseCase,
            ResetPasswordUseCase resetPasswordUseCase,
            ChangePasswordUseCase changePasswordUseCase,
            AuthenticatedSessionEstablisher sessionEstablisher,
            TenantContext tenantContext) {
        this.registerUserUseCase = registerUserUseCase;
        this.verifyEmailUseCase = verifyEmailUseCase;
        this.loginUseCase = loginUseCase;
        this.requestPasswordResetUseCase = requestPasswordResetUseCase;
        this.resetPasswordUseCase = resetPasswordUseCase;
        this.changePasswordUseCase = changePasswordUseCase;
        this.sessionEstablisher = sessionEstablisher;
        this.tenantContext = tenantContext;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@RequestBody RegisterRequest request) {
        TenantSummary tenant = requireTenant();
        RegisterUserResult result = registerUserUseCase.execute(new RegisterUserCommand(
                tenant.tenantId(),
                tenant.slug(),
                request.email(),
                request.givenName(),
                request.familyName(),
                request.password()));
        return new RegisterResponse(result.userId(), result.email());
    }

    @PostMapping("/verify-email")
    public VerifyEmailResponse verifyEmail(@RequestBody VerifyEmailRequest request) {
        // Not tenant-scoped: the token itself (looked up by its hash) already uniquely identifies
        // the user being verified, regardless of which subdomain the request came in on.
        VerifyEmailResult result = verifyEmailUseCase.execute(new VerifyEmailCommand(request.token()));
        return new VerifyEmailResponse(result.userId(), result.email());
    }

    @PostMapping("/login")
    public LoginResponse login(
            @RequestBody LoginRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        TenantSummary tenant = requireTenant();
        LoginOutcome outcome =
                loginUseCase.execute(new LoginCommand(tenant.tenantId(), request.email(), request.password()));
        return switch (outcome) {
            case LoginOutcome.Authenticated authenticated -> {
                sessionEstablisher.establish(authenticated.result(), servletRequest, servletResponse);
                yield LoginResponse.authenticated(authenticated.result().userId(), authenticated.result().email());
            }
            case LoginOutcome.MfaChallengeIssued issued -> LoginResponse.mfaRequired(issued.challengeToken());
        };
    }

    @PostMapping("/forgot-password")
    public ForgotPasswordResponse forgotPassword(@RequestBody ForgotPasswordRequest request) {
        TenantSummary tenant = requireTenant();
        requestPasswordResetUseCase.execute(
                new RequestPasswordResetCommand(tenant.tenantId(), tenant.slug(), request.email()));
        // Always the exact same response regardless of whether the e-mail matched an account -
        // see RequestPasswordResetUseCase's enumeration-safety rationale.
        return new ForgotPasswordResponse();
    }

    @PostMapping("/reset-password")
    public ResetPasswordResponse resetPassword(
            @RequestBody ResetPasswordRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        // Not tenant-scoped: the token itself already uniquely identifies the user being reset,
        // regardless of which subdomain the request came in on (see ResetPasswordCommand).
        ResetPasswordResult result =
                resetPasswordUseCase.execute(new ResetPasswordCommand(request.token(), request.newPassword()));
        // Invalidates only whatever session THIS request happens to be carrying - see
        // AuthenticatedSessionEstablisher#invalidateCurrentSession's Javadoc for the scope
        // limitation: this does not reach across other devices/browsers/sessions for the user.
        sessionEstablisher.invalidateCurrentSession(servletRequest, servletResponse);
        return new ResetPasswordResponse(result.userId(), result.email());
    }

    @PostMapping("/account/change-password")
    public ChangePasswordResponse changePassword(
            @RequestBody ChangePasswordRequest request,
            @AuthenticationPrincipal SsoAuthenticatedPrincipal principal,
            HttpServletRequest servletRequest,
            HttpServletResponse servletResponse) {
        ChangePasswordResult result = changePasswordUseCase.execute(
                new ChangePasswordCommand(principal.userId(), request.currentPassword(), request.newPassword()));
        sessionEstablisher.invalidateCurrentSession(servletRequest, servletResponse);
        return new ChangePasswordResponse(result.userId(), result.email());
    }

    private TenantSummary requireTenant() {
        return tenantContext.tenant().orElseThrow(TenantRequiredException::new);
    }
}
