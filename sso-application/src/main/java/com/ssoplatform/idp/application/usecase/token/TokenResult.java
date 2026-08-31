package com.ssoplatform.idp.application.usecase.token;

/**
 * Output of a successful {@link TokenUseCase#execute}: the freshly signed access token, its
 * validity in seconds, and - only when the relevant scopes included {@code openid} - the signed ID
 * token (OpenID Connect Core 1.0 §2). {@code idToken} is {@code null} otherwise; {@code
 * TokenController} omits the {@code id_token} field from the JSON response entirely in that case
 * rather than emitting a JSON {@code null}.
 *
 * <p>{@link #refreshToken} carries the raw value of a brand-new refresh token, present in exactly
 * two cases: the {@code authorization_code} grant was redeemed with {@code offline_access} among
 * its scopes (starting a new rotation family - see {@code RefreshToken#issueFirst}), or the {@code
 * refresh_token} grant was redeemed successfully (rotating the family forward one step - see
 * {@code RefreshToken#continueFamily}). {@code null} whenever neither applies; {@code
 * TokenController} omits the {@code refresh_token} field from the JSON response in that case
 * rather than emitting a JSON {@code null}, the same way it already treats {@link #idToken}.
 *
 * <p>{@code token_type} is not carried here, since it is always the constant {@code "Bearer"} and
 * is hardcoded by {@code TokenController} rather than threaded through as data with only one
 * possible value.
 */
public record TokenResult(String accessToken, long expiresInSeconds, String idToken, String refreshToken) {}
