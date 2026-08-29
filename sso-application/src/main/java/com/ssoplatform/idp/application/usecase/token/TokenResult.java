package com.ssoplatform.idp.application.usecase.token;

/**
 * Output of a successful {@link TokenUseCase#execute}: the freshly signed access token, its
 * validity in seconds, and - only when the redeemed authorization code carried the {@code openid}
 * scope - the signed ID token (OpenID Connect Core 1.0 §2). {@code idToken} is {@code null}
 * otherwise; {@code TokenController} omits the {@code id_token} field from the JSON response
 * entirely in that case rather than emitting a JSON {@code null}.
 *
 * <p>No {@code refresh_token} field - this grant never issues one, by explicit project decision
 * (see {@code architecture_decisions.md}); {@code token_type} is not carried here either, since it
 * is always the constant {@code "Bearer"} and is hardcoded by {@code TokenController} rather than
 * threaded through as data with only one possible value.
 */
public record TokenResult(String accessToken, long expiresInSeconds, String idToken) {}
