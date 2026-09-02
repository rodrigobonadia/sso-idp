package com.ssoplatform.idp.api.web.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * OIDC Discovery document (OpenID Connect Discovery 1.0 §3), published at {@code GET
 * /.well-known/openid-configuration}. Every field here reflects an OAuth2/OIDC capability this
 * server genuinely implements today - fields for capabilities not yet built ({@code
 * revocation_endpoint}, {@code introspection_endpoint}, etc.) are deliberately omitted entirely
 * rather than advertised as a roadmap placeholder, so a real OIDC client library that trusts this
 * document at face value never attempts to call an endpoint that does not exist yet (see {@code
 * architecture_decisions.md}, Phase 3.5 scope decision). {@code userinfo_endpoint} was added in
 * Phase 3.7, once {@code GET /userinfo} actually existed to be advertised.
 *
 * <p>snake_case field names are mandated by the spec (like {@code TokenResponse}), hence the
 * explicit {@link JsonProperty} annotations.
 */
public record DiscoveryResponse(
        String issuer,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
        @JsonProperty("scopes_supported") List<String> scopesSupported,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("subject_types_supported") List<String> subjectTypesSupported,
        @JsonProperty("id_token_signing_alg_values_supported") List<String> idTokenSigningAlgValuesSupported,
        @JsonProperty("token_endpoint_auth_methods_supported") List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported) {}
