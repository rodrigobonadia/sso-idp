package com.ssoplatform.idp.domain.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

class TenantTest {

    private final TenantSlug slug = TenantSlug.of("acme");

    @Test
    void createsAnActiveTenantWithAGeneratedIdAndCreationTimestamp() {
        Tenant tenant = Tenant.create("Acme Corp", slug);

        assertThat(tenant.id()).isNotNull();
        assertThat(tenant.name()).isEqualTo("Acme Corp");
        assertThat(tenant.slug()).isEqualTo(slug);
        assertThat(tenant.status()).isEqualTo(TenantStatus.ACTIVE);
        assertThat(tenant.isActive()).isTrue();
        assertThat(tenant.createdAt()).isNotNull();
    }

    @Test
    void trimsTheNameOnCreation() {
        Tenant tenant = Tenant.create("  Acme Corp  ", slug);

        assertThat(tenant.name()).isEqualTo("Acme Corp");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void rejectsBlankNameOnCreation(String invalidName) {
        assertThatThrownBy(() -> Tenant.create(invalidName, slug)).isInstanceOf(InvalidTenantNameException.class);
    }

    @Test
    void rejectsNameShorterThanTwoCharacters() {
        assertThatThrownBy(() -> Tenant.create("A", slug)).isInstanceOf(InvalidTenantNameException.class);
    }

    @Test
    void rejectsNameLongerThanOneHundredFiftyCharacters() {
        String tooLong = "A".repeat(151);

        assertThatThrownBy(() -> Tenant.create(tooLong, slug)).isInstanceOf(InvalidTenantNameException.class);
    }

    @Test
    void renameUpdatesTheName() {
        Tenant tenant = Tenant.create("Acme Corp", slug);

        tenant.rename("Acme International");

        assertThat(tenant.name()).isEqualTo("Acme International");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void renameRejectsBlankNames(String invalidName) {
        Tenant tenant = Tenant.create("Acme Corp", slug);

        assertThatThrownBy(() -> tenant.rename(invalidName)).isInstanceOf(InvalidTenantNameException.class);
    }

    @Test
    void suspendTransitionsAnActiveTenantToSuspended() {
        Tenant tenant = Tenant.create("Acme Corp", slug);

        tenant.suspend();

        assertThat(tenant.status()).isEqualTo(TenantStatus.SUSPENDED);
        assertThat(tenant.isActive()).isFalse();
    }

    @Test
    void suspendingAnAlreadySuspendedTenantThrows() {
        Tenant tenant = Tenant.create("Acme Corp", slug);
        tenant.suspend();

        assertThatThrownBy(tenant::suspend).isInstanceOf(TenantStateException.class);
    }

    @Test
    void activateTransitionsASuspendedTenantToActive() {
        Tenant tenant = Tenant.create("Acme Corp", slug);
        tenant.suspend();

        tenant.activate();

        assertThat(tenant.status()).isEqualTo(TenantStatus.ACTIVE);
        assertThat(tenant.isActive()).isTrue();
    }

    @Test
    void activatingAnAlreadyActiveTenantThrows() {
        Tenant tenant = Tenant.create("Acme Corp", slug);

        assertThatThrownBy(tenant::activate).isInstanceOf(TenantStateException.class);
    }

    @Test
    void reconstituteRebuildsAnExistingTenantWithoutRunningCreationLogic() {
        TenantId id = TenantId.generate();
        Instant createdAt = Instant.parse("2026-01-01T00:00:00Z");

        Tenant tenant = Tenant.reconstitute(id, slug, "Acme Corp", TenantStatus.SUSPENDED, createdAt);

        assertThat(tenant.id()).isEqualTo(id);
        assertThat(tenant.status()).isEqualTo(TenantStatus.SUSPENDED);
        assertThat(tenant.createdAt()).isEqualTo(createdAt);
    }

    @Test
    void equalityIsBasedOnId() {
        TenantId id = TenantId.generate();
        Instant createdAt = Instant.now();
        Tenant first = Tenant.reconstitute(id, slug, "Acme Corp", TenantStatus.ACTIVE, createdAt);
        Tenant second = Tenant.reconstitute(id, TenantSlug.of("other-slug"), "Other Name", TenantStatus.SUSPENDED, createdAt);

        assertThat(first).isEqualTo(second);
        assertThat(first).hasSameHashCodeAs(second);
    }
}
