package com.ssoplatform.idp.api.security;

import com.ssoplatform.idp.application.usecase.user.LoginResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

/**
 * Establishes the exact same kind of session for a successful login, regardless of which surface
 * (the Thymeleaf {@code LoginPageController} or the REST {@code AuthApiController}) authenticated
 * it - a single, shared implementation is what guarantees the two never drift apart.
 *
 * <p>Deliberately manual rather than driven by Spring Security's {@code AuthenticationManager}/
 * {@code AuthenticationProvider} machinery: all the real authentication decision already happened
 * in {@link com.ssoplatform.idp.application.usecase.user.LoginUseCase}. This class's only job is
 * to record that decision where Spring Security's filters expect to find it - the
 * {@code SecurityContext}, persisted into the {@code HttpSession} - so that subsequent requests
 * carrying the same session cookie are recognized as authenticated.
 */
@Component
public class AuthenticatedSessionEstablisher {

    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public void establish(LoginResult result, HttpServletRequest request, HttpServletResponse response) {
        SsoAuthenticatedPrincipal principal =
                new SsoAuthenticatedPrincipal(result.userId(), result.tenantId(), result.email());
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null, List.of());

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }
}
