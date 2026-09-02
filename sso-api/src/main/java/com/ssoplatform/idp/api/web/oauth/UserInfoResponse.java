package com.ssoplatform.idp.api.web.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Success response body for {@code GET /userinfo}, shaped per OpenID Connect Core 1.0 §5.3.2:
 * snake_case claim names are mandated by the spec (unlike every other JSON response in this
 * project, which is plain camelCase - see {@code web.rest.ErrorResponse}), hence the explicit
 * {@link JsonProperty} annotations.
 *
 * <p>{@link JsonInclude} on the whole record omits every {@code null} field from the JSON
 * entirely, rather than emitting a literal {@code null} - see {@code UserInfoResult}'s Javadoc for
 * which fields are {@code null} when, based on the presented access token's {@code scope}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserInfoResponse(
        String sub,
        String email,
        @JsonProperty("email_verified") Boolean emailVerified,
        @JsonProperty("given_name") String givenName,
        @JsonProperty("family_name") String familyName,
        String name) {}
