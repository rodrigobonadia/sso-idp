package com.ssoplatform.idp.api.web.oidc;

import java.util.List;

/** A JWKS document (RFC 7517): a set of public keys, keyed by {@code kid}, that a token verifier
 * can use to check a signature without ever needing the private key itself. */
public record JwksResponse(List<JwkResponse> keys) {}
