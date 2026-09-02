package com.ssoplatform.idp.application.usecase.userinfo;

/**
 * Output of {@link GetUserInfoUseCase}, shaped per OpenID Connect Core 1.0 §5.3.2.
 *
 * <p>{@code sub} is always present. Every other field is {@code null} whenever the access token's
 * {@code scope} did not grant it: {@code email}/{@code emailVerified} require the {@code email}
 * scope, {@code givenName}/{@code familyName}/{@code name} require the {@code profile} scope -
 * {@code UserInfoController} omits a {@code null} field from the JSON response entirely rather
 * than emitting a literal {@code null}, matching how a client is expected to treat an absent
 * claim versus one explicitly asserted as empty.
 */
public record UserInfoResult(
        String sub, String email, Boolean emailVerified, String givenName, String familyName, String name) {}
