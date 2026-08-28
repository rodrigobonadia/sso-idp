package com.ssoplatform.idp.api.web.oidc;

/** One entry of a JWKS document (RFC 7517) describing an RSA public signing key. */
public record JwkResponse(String kty, String use, String alg, String kid, String n, String e) {}
