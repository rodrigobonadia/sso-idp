package com.ssoplatform.idp.infrastructure.persistence.adapter;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.DeviceCodeStatus;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.InfrastructureTestConfiguration;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
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
@Import({
    DeviceCodeRepositoryAdapter.class,
    OAuthClientRepositoryAdapter.class,
    TenantRepositoryAdapter.class,
    UserRepositoryAdapter.class,
    InfrastructureTestConfiguration.class
})
@Testcontainers
class DeviceCodeRepositoryAdapterIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private DeviceCodeRepositoryAdapter deviceCodeRepository;

    @Autowired
    private OAuthClientRepositoryAdapter oauthClientRepository;

    @Autowired
    private TenantRepositoryAdapter tenantRepository;

    @Autowired
    private UserRepositoryAdapter userRepository;

    private Tenant tenant;
    private OAuthClient client;
    private User user;

    @BeforeEach
    void setUp() {
        // device_codes has NOT NULL foreign keys to tenants and oauth_clients, and a nullable one
        // to users (unset until approved), so every test needs the first two persisted first.
        tenant = Tenant.create("Acme Corp", TenantSlug.of("acme-device-codes-" + System.nanoTime()));
        tenantRepository.save(tenant);

        client = OAuthClient.register(
                tenant.id(),
                ClientId.of("acme-cli-" + System.nanoTime()),
                ClientSecretHash.of("hashed-secret"),
                "Acme CLI",
                Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.DEVICE_CODE));
        oauthClientRepository.save(client);

        user = User.register(
                tenant.id(),
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$12$hash"));
        userRepository.save(user);
    }

    private DeviceCode newDeviceCode() {
        return DeviceCode.request(
                tenant.id(),
                client.id(),
                TokenHash.of("hash-" + System.nanoTime()),
                UserCode.generate(),
                Set.of("openid", "profile"),
                Instant.now(),
                Duration.ofMinutes(10));
    }

    @Test
    void savesAndReloadsAPendingCodeByItsDeviceCodeHash() {
        DeviceCode deviceCode = newDeviceCode();

        deviceCodeRepository.save(deviceCode);
        Optional<DeviceCode> reloaded = deviceCodeRepository.findByDeviceCodeHash(deviceCode.deviceCodeHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(deviceCode.id());
        assertThat(reloaded.get().tenantId()).isEqualTo(tenant.id());
        assertThat(reloaded.get().oauthClientId()).isEqualTo(client.id());
        assertThat(reloaded.get().userCode()).isEqualTo(deviceCode.userCode());
        assertThat(reloaded.get().scopes()).containsExactlyInAnyOrder("openid", "profile");
        assertThat(reloaded.get().status()).isEqualTo(DeviceCodeStatus.PENDING);
        assertThat(reloaded.get().userId()).isNull();
        assertThat(reloaded.get().lastPolledAt()).isNull();
        assertThat(reloaded.get().redeemedAt()).isNull();
    }

    @Test
    void findsAPendingCodeByItsUserCode() {
        DeviceCode deviceCode = newDeviceCode();
        deviceCodeRepository.save(deviceCode);

        Optional<DeviceCode> reloaded = deviceCodeRepository.findByUserCode(deviceCode.userCode());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().id()).isEqualTo(deviceCode.id());
    }

    @Test
    void findByDeviceCodeHashIsEmptyWhenNoCodeMatches() {
        assertThat(deviceCodeRepository.findByDeviceCodeHash(TokenHash.of("no-such-hash"))).isEmpty();
    }

    @Test
    void findByUserCodeIsEmptyWhenNoCodeMatches() {
        assertThat(deviceCodeRepository.findByUserCode(UserCode.of("ZZZZ-9999"))).isEmpty();
    }

    @Test
    void reloadsAnApprovedCodeWithItsUserAndPollTimestampPreserved() {
        DeviceCode deviceCode = newDeviceCode();
        Instant approvedAt = Instant.now().plusSeconds(5);
        deviceCode.approve(user.id(), approvedAt);
        deviceCode.recordPoll(Instant.now().plusSeconds(6));

        deviceCodeRepository.save(deviceCode);
        Optional<DeviceCode> reloaded = deviceCodeRepository.findByDeviceCodeHash(deviceCode.deviceCodeHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(DeviceCodeStatus.APPROVED);
        assertThat(reloaded.get().userId()).isEqualTo(user.id());
        assertThat(reloaded.get().lastPolledAt()).isNotNull();
    }

    @Test
    void reloadsARedeemedCodeWithItsRedeemedAtPreserved() {
        DeviceCode deviceCode = newDeviceCode();
        deviceCode.approve(user.id(), Instant.now());
        deviceCode.redeem(Instant.now().plusSeconds(1));

        deviceCodeRepository.save(deviceCode);
        Optional<DeviceCode> reloaded = deviceCodeRepository.findByDeviceCodeHash(deviceCode.deviceCodeHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(DeviceCodeStatus.REDEEMED);
        assertThat(reloaded.get().redeemedAt()).isNotNull();
    }

    @Test
    void reloadsADeniedCode() {
        DeviceCode deviceCode = newDeviceCode();
        deviceCode.deny(Instant.now());

        deviceCodeRepository.save(deviceCode);
        Optional<DeviceCode> reloaded = deviceCodeRepository.findByDeviceCodeHash(deviceCode.deviceCodeHash());

        assertThat(reloaded).isPresent();
        assertThat(reloaded.get().status()).isEqualTo(DeviceCodeStatus.DENIED);
        assertThat(reloaded.get().userId()).isNull();
    }
}
