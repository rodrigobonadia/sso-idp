package com.ssoplatform.idp.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

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
 * <p>No custom {@code AuthenticationEntryPoint} is configured, so an unauthenticated request to a
 * protected path (currently {@code GET /account} and the change-password endpoints) gets Spring
 * Security's own default: a plain {@code 403 Forbidden}, with no redirect. That is an acceptable
 * placeholder behavior for this phase's minimal "you are logged in" page; a friendlier
 * redirect-to-login experience can be added later without changing the authentication mechanism
 * itself.
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
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
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
                                "/api/register",
                                "/api/verify-email",
                                "/api/login",
                                "/api/forgot-password",
                                "/api/reset-password")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .logout(logout -> logout.logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
        return http.build();
    }
}
