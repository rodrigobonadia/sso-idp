package com.ssoplatform.idp.application.usecase.signingkey;

/**
 * A tenant's signing key as needed to build one entry of a JWKS document: the {@code kid}, the
 * algorithm, and the public key material (Base64-encoded X.509 DER) that the caller decodes into
 * a {@code java.security.PublicKey} to extract the JWK's {@code n}/{@code e} fields. Deliberately
 * excludes status - the JWKS endpoint publishes every key regardless of whether it is current or
 * retired (see {@code SigningKeyRepository#findAllByTenantId}'s Javadoc) - and, like every other
 * type crossing this boundary, never carries any private key material.
 */
public record SigningKeySummary(String kid, String algorithm, String publicKeyDer) {}
