package com.ssoplatform.idp.api.web.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Success response body for {@code POST /token}, shaped per RFC 6749 §5.1: snake_case field names
 * are mandated by the spec (unlike every other JSON response in this project, which is plain
 * camelCase - see {@code ErrorResponse}), hence the explicit {@link JsonProperty} annotations.
 *
 * <p>{@code idToken} is {@code null} whenever the relevant scopes did not carry {@code openid}
 * (see {@code TokenResult}'s Javadoc), and {@code refreshToken} is {@code null} whenever neither
 * grant issued a new refresh token (see {@code TokenResult}'s Javadoc for the two cases that do).
 * {@link JsonInclude} on the whole record omits both fields entirely from the JSON in those cases,
 * rather than emitting a literal JSON {@code null}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("id_token") String idToken,
        @JsonProperty("refresh_token") String refreshToken) {}
