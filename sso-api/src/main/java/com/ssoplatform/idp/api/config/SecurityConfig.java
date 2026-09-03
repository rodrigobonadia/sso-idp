package com.ssoplatform.idp.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

/**
 * Application-wide HTTP security policy.
 *
 * <p>No {@code UserDetailsService}, {@code AuthenticationProvider}, or {@code .formLogin()}/
 * {@code .httpBasic()} DSL is configured here: this system authenticates through {@link
 * com.ssoplatform.idp.application.usecase.user.LoginUseCase} directly (see {@code
 * LoginPageController} and {@code AuthApiController}), then hands the result to {@link
 * com.ssoplatform.idp.api.security.AuthenticatedSessionEstablisher} to record it as a Spring
 * Security session. This class's only job is authorization (which paths need a session) and the
 * cross-cutting mechanics (CSRF, logout) both surfaces share.
 *
 * <p>CSRF uses {@link CookieCsrfTokenRepository#withHttpOnlyFalse()} so that REST API callers can
 * read the {@code XSRF-TOKEN} cookie themselves and echo it back as an {@code X-XSRF-TOKEN}
 * header on state-changing requests, exactly like the server-rendered Thymeleaf forms already do
 * automatically via the hidden {@code _csrf} field Spring injects into {@code th:action} forms.
 * This requires explicitly setting {@link CsrfTokenRequestAttributeHandler} instead of leaving
 * Spring Security's own default ({@code XorCsrfTokenRequestAttributeHandler}, which BREACH-protects
 * the token by masking it before exposing it to forms/headers): with the masking handler, the
 * value rendered into a Thymeleaf form's hidden {@code _csrf} field is NOT the same as the raw
 * value {@link CookieCsrfTokenRepository} stores in the cookie, so a REST client that reads the
 * cookie and echoes it back verbatim (the pattern this class's Javadoc describes, and the only
 * pattern available to a JSON-only endpoint with no HTML form, like {@code POST
 * /internal/signing-keys}) would always be rejected as an invalid token - even though the exact
 * same value legitimately authenticated the request that just set that cookie. Using the plain
 * (non-masking) handler here means both the cookie and the rendered form field always carry the
 * identical raw token, so the two client patterns behave consistently.
 *
 * <p>No custom {@code AuthenticationEntryPoint} is configured for MOST protected paths, so an
 * unauthenticated request to one of them (currently {@code GET /account} and the change-password
 * endpoints) gets Spring Security's own default: a plain {@code 403 Forbidden}, with no redirect.
 * That is an acceptable placeholder behavior for this phase's minimal "you are logged in" page; a
 * friendlier redirect-to-login experience can be added later without changing the authentication
 * mechanism itself.
 *
 * <p>{@code GET /authorize} (Phase 3.3) and {@code /device} (the Device Authorization Grant's
 * verification page, Phase 3.9) are the deliberate exceptions: {@code
 * .exceptionHandling().defaultAuthenticationEntryPointFor(...)} wires a single {@link
 * LoginUrlAuthenticationEntryPoint}, scoped to an {@link OrRequestMatcher} covering BOTH paths, so
 * an unauthenticated request to either redirects to {@code /login} instead of returning 403 - the
 * standard OAuth UX, where a user who isn't signed in yet still needs to be able to complete the
 * flow after logging in. This works together with a mechanism Spring Security already provides
 * "for free" regardless of which entry point is configured: {@code ExceptionTranslationFilter}
 * always calls {@code RequestCache#saveRequest(...)} (the default {@code HttpSessionRequestCache})
 * before invoking whichever entry point applies, for every unauthenticated request to a protected
 * path - it is only ever USED here, on these two paths, because {@code LoginPageController}'s
 * {@code POST /login} handler explicitly checks that cache after establishing a session and, if a
 * request was saved, redirects there instead of to the usual {@code /account} - see that
 * controller's Javadoc for the resume side of this flow. Only {@code GET /device} is covered
 * (never {@code POST /device}, {@code /device/allow}, or {@code /device/deny}) for the same reason
 * only {@code GET /authorize} ever needed this: {@code LoginPageController}'s resume is a plain
 * redirect to the saved URL, which replays as a GET and would silently drop a POST body - by the
 * time a user reaches one of this platform's own device-verification POSTs, the {@code GET
 * /device} step they came from has already established their session, so those POSTs simply fall
 * under the default {@code anyRequest().authenticated()} rule below like any other protected POST.
 *
 * <p><b>{@code defaultAuthenticationEntryPointFor} gotcha (found by a real {@code mvn clean
 * verify} run, not by inspection):</b> {@link
 * org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer}
 * only builds an actual matcher-dispatching {@code DelegatingAuthenticationEntryPoint} when TWO OR
 * MORE {@code defaultAuthenticationEntryPointFor(...)} mappings are registered; with exactly one
 * mapping (as this class originally had, wiring only the {@code /authorize} entry above), Spring
 * Security uses that single entry point for EVERY unauthenticated request application-wide,
 * silently ignoring its {@link AntPathRequestMatcher} entirely. That regressed every other
 * protected path this class's Javadoc documents as plain-403 ({@code /account}, the
 * change-password endpoints, {@code POST /internal/signing-keys}, etc.) to redirect to
 * {@code /login} instead - caught by five pre-existing, otherwise-unrelated IT classes failing
 * with {@code expected:<403> but was:<302>} the moment Phase 3.3's real build ran. Fixed by
 * registering a SECOND mapping below, {@link Http403ForbiddenEntryPoint} for {@link
 * AnyRequestMatcher#INSTANCE} - with two mappings present, Spring Security builds the real
 * delegating entry point and matches {@code /authorize} first (registration order), falling back
 * to the original 403 behavior for everything else. LESSON: {@code
 * defaultAuthenticationEntryPointFor} must always be called at least twice - a single call is not
 * "one path gets a custom entry point, everything else keeps the default" but "this entry point
 * for all requests," which defeats the whole point of the method's per-path matcher parameter.
 *
 * <p>The "forgot password" flow ({@code /forgot-password*}, {@code /reset-password}, and their
 * REST equivalents) is permitted unauthenticated for the same reason registration and login are:
 * proving a valid session is exactly what someone who forgot their password cannot do. Changing a
 * password while already logged in ({@code /account/change-password}, {@code
 * /api/account/change-password}) is deliberately NOT listed here, since it requires an existing
 * session to identify whose password is being changed.
 *
 * <p>{@code /.well-known/**} (the JWKS document) is permitted unauthenticated on purpose: a JWKS
 * document exists specifically to be fetched by anyone who needs to verify a token's signature,
 * so it must be publicly readable by definition - unlike {@code POST /internal/signing-keys},
 * which is NOT listed here and so falls under the default {@code anyRequest().authenticated()}
 * rule (any logged-in session in the tenant may call it for now - see
 * {@code architecture_decisions.md} for why no stronger, admin-specific protection exists yet).
 *
 * <p>{@code /token} (Phase 3.4) is permitted unauthenticated for the same underlying reason
 * {@code /login} and {@code /register} are: there is no Spring Security session to require in the
 * first place, since the caller being authenticated here is the OAuth CLIENT (via hand-parsed HTTP
 * Basic inside {@code TokenController}/{@code TokenUseCase}), not a resource-owner session.
 *
 * <p>{@code /token} is also the one path excluded from CSRF protection (see {@code
 * ignoringRequestMatchers} below) - CSRF protection exists to stop a malicious page from riding a
 * victim's BROWSER COOKIES into a state-changing request the victim never intended; a real OAuth
 * client calling {@code /token} is a server-to-server HTTP call that carries no browser session
 * cookie at all and authenticates purely via the {@code Authorization} header it explicitly
 * constructs, so it can never present a CSRF token a browser-based flow would have - requiring one
 * would make this endpoint unusable by every real OAuth client, and there is no cookie-riding
 * attack for the exemption to reopen. This mirrors how every real OAuth2/OIDC server (Spring
 * Authorization Server included) exempts its token endpoint from CSRF for the same reason.
 *
 * <p>{@code /userinfo} (Phase 3.7) is permitted unauthenticated for the same underlying reason as {@code
 * /token}: the caller authenticates via a bearer access token (hand-parsed inside {@code
 * UserInfoController}/{@code GetUserInfoUseCase}), not a Spring Security session, so there is nothing for
 * {@code anyRequest().authenticated()} to check here. It needs no CSRF exemption of its own, unlike {@code
 * /token}: it is a {@code GET} request, and Spring Security's CSRF filter only ever protects the unsafe
 * HTTP methods to begin with.
 *
 * <p>{@code /device_authorization} (Phase 3.9, RFC 8628) is permitted unauthenticated and CSRF-exempt
 * for the exact same reason as {@code /token}: the caller is the OAuth CLIENT itself (a device with no
 * browser at all, in the common case), authenticated by {@code RequestDeviceAuthorizationUseCase} via
 * HTTP Basic or a public client's bare {@code client_id} - never a Spring Security session - so there is
 * no resource-owner session to require and no browser cookie a CSRF attack could ride along with.
 * {@code /device} (the human-facing verification page for the SAME grant) is the opposite: it very much
 * needs a resource-owner session, exactly like {@code /authorize} - see the entry-point paragraph above.
 *
 * <p>{@code /introspect} (RFC 7662) and {@code /revoke} (RFC 7009), added in Phase 3.10, are permitted
 * unauthenticated and CSRF-exempt for the exact same reason as {@code /token}: both authenticate the
 * calling OAuth CLIENT itself via hand-parsed HTTP Basic ({@code IntrospectTokenUseCase}/{@code
 * RevokeTokenUseCase}), never a Spring Security session, so there is no resource-owner session to
 * require and no browser cookie a CSRF attack could ride along with.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                        .ignoringRequestMatchers("/token", "/device_authorization", "/introspect", "/revoke"))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/actuator/**",
                                "/.well-known/**",
                                "/register",
                                "/register/**",
                                "/verify-email",
                                "/login",
                                "/forgot-password",
                                "/forgot-password/**",
                                "/reset-password",
                                "/token",
                                "/userinfo",
                                "/device_authorization",
                                "/introspect",
                                "/revoke",
                                "/api/register",
                                "/api/verify-email",
                                "/api/login",
                                "/api/forgot-password",
                                "/api/reset-password")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new OrRequestMatcher(
                                        new AntPathRequestMatcher("/authorize"), new AntPathRequestMatcher("/device")))
                        .defaultAuthenticationEntryPointFor(
                                new Http403ForbiddenEntryPoint(), AnyRequestMatcher.INSTANCE))
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
        return http.build();
    }
}
