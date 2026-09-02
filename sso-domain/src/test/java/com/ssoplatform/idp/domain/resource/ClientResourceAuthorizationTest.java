package com.ssoplatform.idp.domain.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ClientResourceAuthorizationTest {

    private final TenantId tenantId = TenantId.generate();
    private final OAuthClientId oauthClientId = OAuthClientId.generate();
    private final ResourceId resourceId = ResourceId.generate();
    private final Set<String> grantedScopes = Set.of("orders:read");

    private ClientResourceAuthorization authorize() {
        return ClientResourceAuthorization.authorize(tenantId, oauthClientId, resourceId, grantedScopes);
    }

    @Test
    void authorizesWithAGeneratedIdAndCreationTimestamp() {
        ClientResourceAuthorization authorization = authorize();

        assertThat(authorization.id()).isNotNull();
        assertThat(authorization.tenantId()).isEqualTo(tenantId);
        assertThat(authorization.oauthClientId()).isEqualTo(oauthClientId);
        assertThat(authorization.resourceId()).isEqualTo(resourceId);
        assertThat(authorization.grantedScopes()).isEqualTo(grantedScopes);
        assertThat(authorization.createdAt()).isNotNull();
    }

    @Test
    void rejectsEmptyGrantedScopes() {
        assertThatThrownBy(() -> ClientResourceAuthorization.authorize(tenantId, oauthClientId, resourceId, Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsABlankGrantedScope() {
        assertThatThrownBy(
                        () -> ClientResourceAuthorization.authorize(tenantId, oauthClientId, resourceId, Set.of(" ")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAGrantedScopeContainingWhitespace() {
        assertThatThrownBy(() -> ClientResourceAuthorization.authorize(
                        tenantId, oauthClientId, resourceId, Set.of("orders read")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void grantsScopeReflectsOnlyTheGrantedSubset() {
        ClientResourceAuthorization authorization = authorize();

        assertThat(authorization.grantsScope("orders:read")).isTrue();
        assertThat(authorization.grantsScope("orders:write")).isFalse();
    }

    @Test
    void twoAuthorizationsWithTheSameIdAreEqual() {
        ClientResourceAuthorization authorization = authorize();
        ClientResourceAuthorization reconstituted = ClientResourceAuthorization.reconstitute(
                authorization.id(),
                authorization.tenantId(),
                authorization.oauthClientId(),
                authorization.resourceId(),
                authorization.grantedScopes(),
                authorization.createdAt());

        assertThat(authorization).isEqualTo(reconstituted);
        assertThat(authorization).hasSameHashCodeAs(reconstituted);
    }
}
