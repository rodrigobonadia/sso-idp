package com.ssoplatform.idp.api.web.oauth;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Success response body for {@code POST /device_authorization}, shaped per RFC 8628 §3.2:
 * snake_case field names are mandated by the spec, exactly like {@code TokenResponse} - hence the
 * explicit {@link JsonProperty} annotations.
 */
public record DeviceAuthorizationResponse(
        @JsonProperty("device_code") String deviceCode,
        @JsonProperty("user_code") String userCode,
        @JsonProperty("verification_uri") String verificationUri,
        @JsonProperty("verification_uri_complete") String verificationUriComplete,
        @JsonProperty("expires_in") long expiresIn,
        long interval) {}
