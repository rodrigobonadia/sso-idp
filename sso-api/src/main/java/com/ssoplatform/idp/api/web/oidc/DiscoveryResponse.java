package com.ssoplatform.idp.api.web.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * OIDC Discovery document (OpenID Connect Discovery 1.0 §3), published at {@code GET
 * /.well-known/openid-configuration}. Every field here reflects an OAuth2/OIDC capability this
 * server genuinely implements today - a capability not yet built is deliberately omitted entirely
 * rather than advertised as a roadmap placeholder, so a real OIDC client library that trusts this
 * document at face value never attempts to call an endpoint that does not exist yet (see {@code
 * architecture_decisions.md}, Phase 3.5 scope decision). {@code userinfo_endpoint} was added in
 * Phase 3.7, once {@code GET /userinfo} actually existed to be advertised; {@code
 * grant_types_supported} grew from just {@code authorization_code} to also list {@code
 * refresh_token}, {@code client_credentials}, and {@code
 * urn:ietf:params:oauth:grant-type:device_code} once Phase 3.6, Phase 3.8, and Phase 3.9
 * respectively made those grants real (the {@code refresh_token} addition being a small drive-by
 * correction to a gap Phase 3.6 itself left in this document - see {@code
 * architecture_decisions.md}). {@code device_authorization_endpoint} (RFC 8628 §4) and the
 * {@code "none"} entry in {@code token_endpoint_auth_methods_supported} were both added in Phase
 * 3.9 alongside public client support - see {@code OAuthClient#isPublic()}. {@code
 * introspection_endpoint} (RFC 7662 §2) and {@code revocation_endpoint} (RFC 7009 §2) were
 * added in Phase 3.10, once {@code POST /introspect} and {@code POST /revoke} actually existed to
 * be advertised.
 *
 * <p>snake_case field names are mandated by the spec (like {@code TokenResponse}), hence the
 * explicit {@link JsonProperty} annotations.
 */
public record DiscoveryResponse(
        String issuer,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("device_authorization_endpoint") String deviceAuthorizationEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
        @JsonProperty("introspection_endpoint") String introspectionEndpoint,
        @JsonProperty("revocation_endpoint") String revocationEndpoint,
        @JsonProperty("scopes_supported") List<String> scopesSupported,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("subject_types_supported") List<String> subjectTypesSupported,
        @JsonProperty("id_token_signing_alg_values_supported") List<String> idTokenSigningAlgValuesSupported,
        @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported) {}
