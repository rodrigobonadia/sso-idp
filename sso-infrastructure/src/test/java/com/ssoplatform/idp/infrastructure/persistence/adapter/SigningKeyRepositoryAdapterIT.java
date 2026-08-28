package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.KeyId;
import com.ssoplatform.idp.domain.signingkey.PublicKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.signingkey.SigningKeyStatus;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Import;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({SigningKeyRepositoryAdapter.class, TenantRepositoryAdapter.class, InfrastructureTestConfiguration.class})
@Testcontainers
class SigningKeyRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private SigningKeyRepositoryAdapter signingKeyRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        // signing_keys.tenant_id has a foreign key to tenants(id).
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-signing-keys-" + System.nanoTime()));
        tenantRepository.save(tenant);
    }

    private SigningKey newKey(String publicKeyValue) {
        return SigningKey.generate(
                tenant.id(),
                KeyId.generate(),
                PublicKeyMaterial.of(publicKeyValue),
                EncryptedPrivateKeyMaterial.of("ZW5jcnlwdGVkLXByaXZhdGUta2V5"));
    }

    @Test
    void savesAndReloadsAKeyAsTheTenantsCurrentKey() {
        SigningKey key = newKey("cHVibGljLWtleS0x");

        signingKeyRepository.save(key);
        Optional<SigningKey> reloaded = signingKeyRepository.findCurrentByTenantId(tenant.id());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(key.id());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().kid()).isEqualTo(key.kid());
        assertThat(reloaded.get().algorithm()).isEqualTo(SigningKey.ALGORITHM);
        assertThat(reloaded.get().publicKey().value()).isEqualTo("cHVibGljLWtleS0x");
        assertThat(reloaded.get().status()).isEqualTo(SigningKeyStatus.CURRENT);
    }

    @Test
    void findCurrentByTenantIdIsEmptyWhenTheTenantHasNoKeyYet() {
        assertThat(signingKeyRepository.findCurrentByTenantId(tenant.id())).isEmpty();
    }

    @Test
    void findAllByTenantIdReturnsBothCurrentAndRetiredKeys() {
        SigningKey retired = newKey("cHVibGljLWtleS1yZXRpcmVk");
        retired.retire();
        signingKeyRepository.save(retired);
        SigningKey current = newKey("cHVibGljLWtleS1jdXJyZW50");
        signingKeyRepository.save(current);

        List<SigningKey> all = signingKeyRepository.findAllByTenantId(tenant.id());

        assertThat(all).hasSize(2);
        assertThat(all).extracting(SigningKey::status)
                .containsExactlyInAnyOrder(SigningKeyStatus.CURRENT, SigningKeyStatus.RETIRED);
    }

    @Test
    void aRetiredKeyReloadsWithItsStatusPreserved() {
        SigningKey key = newKey("cHVibGljLWtleS0y");
        key.retire();

        signingKeyRepository.save(key);
        List<SigningKey> all = signingKeyRepository.findAllByTenantId(tenant.id());

        assertThat(all).hasSize(1);
        assertThat(all.get(0).status()).isEqualTo(SigningKeyStatus.RETIRED);
        assertThat(signingKeyRepository.findCurrentByTenantId(tenant.id())).isEmpty();
    }
}
