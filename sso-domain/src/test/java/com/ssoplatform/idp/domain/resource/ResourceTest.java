package com.ssoplatform.idp.domain.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ResourceTest {

    private final TenantId tenantId = TenantId.generate();
    private final ResourceIdentifier identifier = ResourceIdentifier.of("https://api.example.com/orders");
    private final Set<String> scopes = Set.of("orders:read", "orders:write");

    private Resource register() {
        return Resource.register(tenantId, identifier, "Orders API", scopes);
    }

    @Test
    void registersAnActiveResourceWithAGeneratedIdAndCreationTimestamp() {
        Resource resource = register();

        assertThat(resource.id()).isNotNull();
        assertThat(resource.tenantId()).isEqualTo(tenantId);
        assertThat(resource.identifier()).isEqualTo(identifier);
        assertThat(resource.name()).isEqualTo("Orders API");
        assertThat(resource.scopes()).isEqualTo(scopes);
        assertThat(resource.status()).isEqualTo(ResourceStatus.ACTIVE);
        assertThat(resource.isUsable()).isTrue();
        assertThat(resource.createdAt()).isNotNull();
    }

    @Test
    void trimsTheNameOnRegistration() {
        Resource resource = Resource.register(tenantId, identifier, "  Orders API  ", scopes);

        assertThat(resource.name()).isEqualTo("Orders API");
    }

    @Test
    void rejectsBlankName() {
        assertThatThrownBy(() -> Resource.register(tenantId, identifier, "  ", scopes))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsEmptyScopes() {
        assertThatThrownBy(() -> Resource.register(tenantId, identifier, "Orders API", Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsABlankScope() {
        assertThatThrownBy(() -> Resource.register(tenantId, identifier, "Orders API", Set.of(" ")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAScopeContainingWhitespace() {
        assertThatThrownBy(() -> Resource.register(tenantId, identifier, "Orders API", Set.of("orders read")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void supportsScopeReflectsTheResourcesOwnCatalog() {
        Resource resource = register();

        assertThat(resource.supportsScope("orders:read")).isTrue();
        assertThat(resource.supportsScope("orders:cancel")).isFalse();
    }

    @Test
    void renameTrimsAndReplacesTheName() {
        Resource resource = register();

        resource.rename("  Orders API v2  ");

        assertThat(resource.name()).isEqualTo("Orders API v2");
    }

    @Test
    void renameRejectsBlankName() {
        Resource resource = register();

        assertThatThrownBy(() -> resource.rename(" ")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void disableThenEnableRoundTrips() {
        Resource resource = register();

        resource.disable();
        assertThat(resource.status()).isEqualTo(ResourceStatus.DISABLED);
        assertThat(resource.isUsable()).isFalse();

        resource.enable();
        assertThat(resource.status()).isEqualTo(ResourceStatus.ACTIVE);
        assertThat(resource.isUsable()).isTrue();
    }

    @Test
    void disablingAnAlreadyDisabledResourceThrows() {
        Resource resource = register();
        resource.disable();

        assertThatThrownBy(resource::disable).isInstanceOf(ResourceStateException.class);
    }

    @Test
    void enablingAnAlreadyActiveResourceThrows() {
        Resource resource = register();

        assertThatThrownBy(resource::enable).isInstanceOf(ResourceStateException.class);
    }

    @Test
    void twoResourcesWithTheSameIdAreEqual() {
        Resource resource = register();
        Resource reconstituted = Resource.reconstitute(
                resource.id(),
                resource.tenantId(),
                resource.identifier(),
                resource.name(),
                resource.scopes(),
                resource.status(),
                resource.createdAt());

        assertThat(resource).isEqualTo(reconstituted);
        assertThat(resource).hasSameHashCodeAs(reconstituted);
    }
}
