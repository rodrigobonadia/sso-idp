package com.ssoplatform.idp.application.usecase.device;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.DeviceAuthorizationNotFoundException;
import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindDeviceAuthorizationUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final TenantId OTHER_TENANT_ID = TenantId.generate();

    @Mock
    private DeviceCodeRepository deviceCodeRepository;

    @Mock
    private OAuthClientRepository oauthClientRepository;

    private FindDeviceAuthorizationUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new FindDeviceAuthorizationUseCase(deviceCodeRepository, oauthClientRepository);
    }

    private static OAuthClient client() {
        return OAuthClient.register(
                TENANT_ID,
                ClientId.of("acme-cli"),
                com.ssoplatform.idp.domain.oauth.ClientSecretHash.of("stored-hash"),
                "Acme CLI",
                Set.of(),
                Set.of("openid"),
                Set.of(GrantType.DEVICE_CODE));
    }

    private static DeviceCode pendingDeviceCodeFor(OAuthClient client, UserCode userCode, TenantId tenantId) {
        return DeviceCode.request(
                tenantId,
                client.id(),
                TokenHash.of("device-code-hash"),
                userCode,
                Set.of("openid"),
                Instant.now(),
                Duration.ofMinutes(10));
    }

    @Test
    void resolvesAPendingUserCodeToItsClientName() {
        UserCode userCode = UserCode.generate();
        OAuthClient client = client();
        DeviceCode deviceCode = pendingDeviceCodeFor(client, userCode, TENANT_ID);
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));
        when(oauthClientRepository.findById(client.id())).thenReturn(Optional.of(client));

        DeviceAuthorizationView view =
                useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), userCode.formatted()));

        assertThat(view.userCode()).isEqualTo(userCode.formatted());
        assertThat(view.clientName()).isEqualTo("Acme CLI");
    }

    @Test
    void acceptsAUserCodeWithoutTheDisplayDash() {
        UserCode userCode = UserCode.generate();
        OAuthClient client = client();
        DeviceCode deviceCode = pendingDeviceCodeFor(client, userCode, TENANT_ID);
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));
        when(oauthClientRepository.findById(client.id())).thenReturn(Optional.of(client));

        DeviceAuthorizationView view =
                useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), userCode.value()));

        assertThat(view.userCode()).isEqualTo(userCode.formatted());
    }

    @Test
    void rejectsAMalformedUserCode() {
        assertThatThrownBy(() -> useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), "!!!")))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
        verify(deviceCodeRepository, never()).findByUserCode(any());
    }

    @Test
    void rejectsABlankUserCode() {
        assertThatThrownBy(() -> useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), "")))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
    }

    @Test
    void rejectsAUserCodeThatDoesNotExist() {
        UserCode userCode = UserCode.generate();
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), userCode.formatted())))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
    }

    @Test
    void rejectsAUserCodeBelongingToAnotherTenant() {
        UserCode userCode = UserCode.generate();
        OAuthClient client = client();
        DeviceCode deviceCode = pendingDeviceCodeFor(client, userCode, OTHER_TENANT_ID);
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));

        assertThatThrownBy(() -> useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), userCode.formatted())))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
    }

    @Test
    void rejectsAUserCodeThatWasAlreadyApproved() {
        UserCode userCode = UserCode.generate();
        OAuthClient client = client();
        DeviceCode deviceCode = pendingDeviceCodeFor(client, userCode, TENANT_ID);
        deviceCode.approve(com.ssoplatform.idp.domain.user.UserId.generate(), Instant.now());
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));

        assertThatThrownBy(() -> useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), userCode.formatted())))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
    }

    @Test
    void rejectsAnExpiredUserCode() {
        UserCode userCode = UserCode.generate();
        OAuthClient client = client();
        DeviceCode deviceCode = DeviceCode.request(
                TENANT_ID,
                client.id(),
                TokenHash.of("device-code-hash"),
                userCode,
                Set.of("openid"),
                Instant.now().minus(Duration.ofMinutes(20)),
                Duration.ofMinutes(10));
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));

        assertThatThrownBy(() -> useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), userCode.formatted())))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
    }

    @Test
    void rejectsWhenTheOwningClientCannotBeFound() {
        UserCode userCode = UserCode.generate();
        OAuthClient client = client();
        DeviceCode deviceCode = pendingDeviceCodeFor(client, userCode, TENANT_ID);
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));
        when(oauthClientRepository.findById(client.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new FindDeviceAuthorizationCommand(TENANT_ID.value(), userCode.formatted())))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
    }
}
