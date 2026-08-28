package com.ssoplatform.idp.domain.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class OAuthClientTest {

    private final TenantId tenantId = TenantId.generate();
    private final ClientId clientId = ClientId.of("acme-test-app");
    private final ClientSecretHash secretHash = ClientSecretHash.of("hashed-secret");
    private final Set<RedirectUri> redirectUris = Set.of(RedirectUri.of("https://app.example.com/callback"));
    private final Set<String> scopes = Set.of("openid", "profile");
    private final Set<GrantType> grantTypes = Set.of(GrantType.AUTHORIZATION_CODE);

    private OAuthClient register() {
        return OAuthClient.register(tenantId, clientId, secretHash, "Acme Test App", redirectUris, scopes, grantTypes);
    }

    @Test
    void registersAnActiveClientWithAGeneratedIdAndCreationTimestamp() {
        OAuthClient client = register();

        assertThat(client.id()).isNotNull();
        assertThat(client.tenantId()).isEqualTo(tenantId);
        assertThat(client.clientId()).isEqualTo(clientId);
        assertThat(client.clientSecretHash()).isEqualTo(secretHash);
        assertThat(client.name()).isEqualTo("Acme Test App");
        assertThat(client.redirectUris()).isEqualTo(redirectUris);
        assertThat(client.allowedScopes()).isEqualTo(scopes);
        assertThat(client.allowedGrantTypes()).containsExactlyInAnyOrder(GrantType.AUTHORIZATION_CODE);
        assertThat(client.status()).isEqualTo(OAuthClientStatus.ACTIVE);
        assertThat(client.isUsable()).isTrue();
        assertThat(client.createdAt()).isNotNull();
    }

    @Test
    void trimsTheNameOnRegistration() {
        OAuthClient client = OAuthClient.register(
                tenantId, clientId, secretHash, "  Acme Test App  ", redirectUris, scopes, grantTypes);

        assertThat(client.name()).isEqualTo("Acme Test App");
    }

    @Test
    void rejectsBlankName() {
        assertThatThrownBy(() ->
                        OAuthClient.register(tenantId, clientId, secretHash, "  ", redirectUris, scopes, grantTypes))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsEmptyRedirectUris() {
        assertThatThrownBy(() ->
                        OAuthClient.register(tenantId, clientId, secretHash, "Acme", Set.of(), scopes, grantTypes))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsEmptyScopes() {
        assertThatThrownBy(() -> OAuthClient.register(
                        tenantId, clientId, secretHash, "Acme", redirectUris, Set.of(), grantTypes))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAScopeThePlatformDoesNotSupport() {
        assertThatThrownBy(() -> OAuthClient.register(
                        tenantId, clientId, secretHash, "Acme", redirectUris, Set.of("unsupported-scope"), grantTypes))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsEmptyGrantTypes() {
        assertThatThrownBy(() ->
                        OAuthClient.register(tenantId, clientId, secretHash, "Acme", redirectUris, scopes, Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void renameUpdatesTheName() {
        OAuthClient client = register();

        client.rename("New Name");

        assertThat(client.name()).isEqualTo("New Name");
    }

    @Test
    void rotateSecretReplacesTheStoredHash() {
        OAuthClient client = register();
        ClientSecretHash newHash = ClientSecretHash.of("new-hashed-secret");

        client.rotateSecret(newHash);

        assertThat(client.clientSecretHash()).isEqualTo(newHash);
    }

    @Test
    void disableTransitionsAnActiveClientToDisabled() {
        OAuthClient client = register();

        client.disable();

        assertThat(client.status()).isEqualTo(OAuthClientStatus.DISABLED);
        assertThat(client.isUsable()).isFalse();
    }

    @Test
    void disablingAnAlreadyDisabledClientThrows() {
        OAuthClient client = register();
        client.disable();

        assertThatThrownBy(client::disable).isInstanceOf(OAuthClientStateException.class);
    }

    @Test
    void enableTransitionsADisabledClientBackToActive() {
        OAuthClient client = register();
        client.disable();

        client.enable();

        assertThat(client.status()).isEqualTo(OAuthClientStatus.ACTIVE);
        assertThat(client.isUsable()).isTrue();
    }

    @Test
    void enablingAnAlreadyActiveClientThrows() {
        OAuthClient client = register();

        assertThatThrownBy(client::enable).isInstanceOf(OAuthClientStateException.class);
    }

    @Test
    void isRedirectUriRegisteredMatchesOnlyExactValues() {
        OAuthClient client = register();

        assertThat(client.isRedirectUriRegistered(RedirectUri.of("https://app.example.com/callback"))).isTrue();
        assertThat(client.isRedirectUriRegistered(RedirectUri.of("https://app.example.com/callback/evil")))
                .isFalse();
    }

    @Test
    void supportsScopeReflectsOnlyAllowedScopes() {
        OAuthClient client = register();

        assertThat(client.supportsScope("openid")).isTrue();
        assertThat(client.supportsScope("email")).isFalse();
    }

    @Test
    void supportsGrantTypeReflectsOnlyAllowedGrantTypes() {
        OAuthClient client = register();

        assertThat(client.supportsGrantType(GrantType.AUTHORIZATION_CODE)).isTrue();
        assertThat(client.supportsGrantType(GrantType.CLIENT_CREDENTIALS)).isFalse();
    }

    @Test
    void reconstituteRebuildsAnExistingClientWithoutRunningRegistrationLogic() {
        OAuthClientId id = OAuthClientId.generate();
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");

        OAuthClient client = OAuthClient.reconstitute(
                id,
                tenantId,
                clientId,
                secretHash,
                "Acme Test App",
                redirectUris,
                scopes,
                grantTypes,
                OAuthClientStatus.DISABLED,
                createdAt);

        assertThat(client.id()).isEqualTo(id);
        assertThat(client.status()).isEqualTo(OAuthClientStatus.DISABLED);
        assertThat(client.createdAt()).isEqualTo(createdAt);
    }

    @Test
    void equalityIsBasedOnId() {
        OAuthClientId id = OAuthClientId.generate();
        Instant createdAt = Instant.now();
        OAuthClient first = OAuthClient.reconstitute(
                id, tenantId, clientId, secretHash, "Acme", redirectUris, scopes, grantTypes,
                OAuthClientStatus.ACTIVE, createdAt);
        OAuthClient second = OAuthClient.reconstitute(
                id, tenantId, ClientId.of("other-client"), secretHash, "Other", redirectUris, scopes, grantTypes,
                OAuthClientStatus.DISABLED, createdAt);

        assertThat(first).isEqualTo(second);
        assertThat(first).hasSameHashCodeAs(second);
    }
}
