package com.ssoplatform.idp.domain.signingkey;

/** Lifecycle status of a {@link SigningKey}. Unlike {@code OAuthClientStatus}'s two interchangeable
 * states, these two are ordered: every tenant has at most one {@link #CURRENT} key at a time (the
 * one used to sign new tokens), plus zero or more {@link #RETIRED} keys kept around purely so
 * tokens already issued under them can still be verified via the JWKS endpoint. */
public enum SigningKeyStatus {
    /** The key currently used to sign new ID Tokens/Access Tokens for its tenant. */
    CURRENT,
    /** No longer used to sign anything new, but still published in the JWKS document so
     * previously issued tokens remain verifiable. */
    RETIRED
}
