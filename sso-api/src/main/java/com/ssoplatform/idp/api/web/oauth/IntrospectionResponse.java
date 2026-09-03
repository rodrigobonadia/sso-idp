package com.ssoplatform.idp.api.web.oauth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response body for {@code POST /introspect}, per RFC 7662 §2.2. {@code active} is the only field
 * ever present when the token is not valid ({@code @JsonInclude(NON_NULL)} drops every other,
 * {@code null} field from the JSON in that case) - {@code IntrospectTokenResult.inactive()} is the
 * only source of such a response, see its Javadoc.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record IntrospectionResponse(
        boolean active,
        String scope,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("token_type") String tokenType,
        Long exp,
        Long iat,
        String sub,
        String aud,
        String iss,
        String jti) {}
