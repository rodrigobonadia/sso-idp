package com.ssoplatform.idp.api.web.rest;

import com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher;
import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import com.ssoplatform.idp.application.usecase.user.LoginCommand;
import com.ssoplatform.idp.application.usecase.user.LoginResult;
import com.ssoplatform.idp.application.usecase.user.LoginUseCase;
import com.ssoplatform.idp.application.usecase.user.RegisterUserCommand;
import com.ssoplatform.idp.application.usecase.user.RegisterUserResult;
import com.ssoplatform.idp.application.usecase.user.RegisterUserUseCase;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailCommand;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailResult;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailUseCase;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
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
    private final AuthenticatedSessionEstablisher sessionEstablisher;
    private final TenantContext tenantContext;

    public AuthApiController(
            RegisterUserUseCase registerUserUseCase,
            VerifyEmailUseCase verifyEmailUseCase,
            LoginUseCase loginUseCase,
            AuthenticatedSessionEstablisher sessionEstablisher,
            TenantContext tenantContext) {
        this.registerUserUseCase = registerUserUseCase;
        this.verifyEmailUseCase = verifyEmailUseCase;
        this.loginUseCase = loginUseCase;
        this.sessionEstablisher = sessionEstablisher;
        this.tenantContext = tenantContext;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public RegisterResponse register(@RequestBody RegisterRequest request) {
        TenantSummary tenant = requireTenant();
        RegisterUserResult result = registerUserUseCase.execute(
                new RegisterUserCommand(tenant.tenantId(), tenant.slug(), request.email(), request.password()));
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
        LoginResult result =
                loginUseCase.execute(new LoginCommand(tenant.tenantId(), request.email(), request.password()));
        sessionEstablisher.establish(result, servletRequest, servletResponse);
        return new LoginResponse(result.userId(), result.email());
    }

    private TenantSummary requireTenant() {
        return tenantContext.tenant().orElseThrow(TenantRequiredException::new);
    }
}
