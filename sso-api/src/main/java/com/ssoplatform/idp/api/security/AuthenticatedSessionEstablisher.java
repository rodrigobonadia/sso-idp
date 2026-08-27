package com.ssoplatform.idp.api.security;

import com.ssoplatform.idp.application.usecase.user.LoginResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
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
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();

    public void establish(LoginResult result, HttpServletRequest request, HttpServletResponse response) {
        SsoAuthenticatedPrincipal principal =
                new SsoAuthenticatedPrincipal(result.userId(), result.tenantId(), result.email());
        Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null, List.of());

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }

    /**
     * Invalidates whatever session the current request is carrying, exactly like Spring
     * Security's own {@code /logout} handler does ({@link SecurityContextLogoutHandler}: session
     * invalidation, clearing the {@code SecurityContext}). Used after a password change (whether
     * via the "forgot password" e-mail flow or the authenticated change-password flow), so a
     * session established with the OLD password can never keep working after a caller has proven
     * they now know a new one - the caller must sign in again.
     *
     * <p>Safe to call even when the request carries no session at all (e.g. a REST client resetting
     * a password without ever having logged in): {@link SecurityContextLogoutHandler} tolerates a
     * request with nothing to invalidate.
     *
     * <p><b>Scope limitation:</b> this only invalidates the session (if any) carried by THIS
     * request - it cannot reach any OTHER session the same user might have open elsewhere (a
     * different browser, a different device, a tab that never re-submits this request). For the
     * authenticated change-password flow that is exactly the right session (the caller who just
     * changed their own password). For the unauthenticated "forgot password" flow, however, the
     * request that submits the new password is usually NOT the same session as any stale login the
     * user still has open elsewhere - that stale session keeps working, unaffected, until it
     * naturally expires. Closing every session for a user on reset would require a server-side,
     * per-user session registry (e.g. Spring Session backed by a shared store, indexed by user id)
     * - a deliberate, larger scope decision this phase does not implement.
     */
    public void invalidateCurrentSession(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        logoutHandler.logout(request, response, authentication);
    }
}
