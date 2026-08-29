package com.ssoplatform.idp.api.web.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Success response body for {@code POST /token}, shaped per RFC 6749 §5.1: snake_case field names
 * are mandated by the spec (unlike every other JSON response in this project, which is plain
 * camelCase - see {@code ErrorResponse}), hence the explicit {@link JsonProperty} annotations.
 *
 * <p>{@code idToken} is {@code null} whenever the redeemed authorization code did not carry the
 * {@code openid} scope (see {@code TokenResult}'s Javadoc) - {@link JsonInclude} on the whole
 * record omits the {@code id_token} field entirely from the JSON in that case, rather than
 * emitting a literal JSON {@code null}.
 *
 * <p>No {@code refresh_token} field - this grant never issues one, by explicit project decision.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("id_token") String idToken) {}
