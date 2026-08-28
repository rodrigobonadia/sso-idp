package com.ssoplatform.idp.domain.oauth;

/**
 * OAuth2 grant types a client may be authorized to use. Only {@link #AUTHORIZATION_CODE} has an
 * actual token-issuing endpoint implemented so far (Phase 3, in progress); the other three are
 * modeled here already so that {@link OAuthClient#allowedGrantTypes()} - and therefore the SQL
 * used to provision a client - never needs to change shape once each grant's endpoint is built,
 * only what a given client is permitted to use.
 */
public enum GrantType {
    AUTHORIZATION_CODE,
    CLIENT_CREDENTIALS,
    REFRESH_TOKEN,
    DEVICE_CODE
}
