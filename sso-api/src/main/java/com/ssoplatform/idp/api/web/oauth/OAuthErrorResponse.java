package com.ssoplatform.idp.api.web.oauth;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Error response body for {@code POST /token}, per RFC 6749 §5.2: {@code {"error": ...,
 * "error_description": ...}}. Distinct from {@code web.rest.ErrorResponse} (which carries only a
 * single {@code error} field and is used by {@code ApiExceptionHandler}) because the token
 * endpoint's error shape is fixed by the OAuth2 spec itself, including the {@code
 * error_description} field that endpoint's callers (OAuth client libraries) generally expect.
 */
public record OAuthErrorResponse(String error, @JsonProperty("error_description") String errorDescription) {}
