package com.ssoplatform.idp.application.usecase.device;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.DeviceAuthorizationNotFoundException;
import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.DeviceCodeStatus;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
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
class DecideDeviceAuthorizationUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final TenantId OTHER_TENANT_ID = TenantId.generate();
    private static final UserId USER_ID = UserId.generate();
    private static final OAuthClientId CLIENT_ID = OAuthClient.register(
                    TENANT_ID,
                    ClientId.of("acme-cli"),
                    ClientSecretHash.of("stored-hash"),
                    "Acme CLI",
                    Set.of(),
                    Set.of("openid"),
                    Set.of(GrantType.DEVICE_CODE))
            .id();

    @Mock
    private DeviceCodeRepository deviceCodeRepository;

    private DecideDeviceAuthorizationUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new DecideDeviceAuthorizationUseCase(deviceCodeRepository);
    }

    private static DeviceCode pendingDeviceCodeFor(UserCode userCode, TenantId tenantId) {
        return DeviceCode.request(
                tenantId,
                CLIENT_ID,
                TokenHash.of("device-code-hash"),
                userCode,
                Set.of("openid"),
                Instant.now(),
                Duration.ofMinutes(10));
    }

    private static DecideDeviceAuthorizationCommand command(String rawUserCode, DeviceAuthorizationDecision decision) {
        return new DecideDeviceAuthorizationCommand(TENANT_ID.value(), USER_ID.value(), rawUserCode, decision);
    }

    @Test
    void approvingAPendingCodeMarksItApprovedAndSavesIt() {
        UserCode userCode = UserCode.generate();
        DeviceCode deviceCode = pendingDeviceCodeFor(userCode, TENANT_ID);
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));
        when(deviceCodeRepository.save(any(DeviceCode.class))).thenAnswer(invocation -> invocation.getArgument(0));

        useCase.execute(command(userCode.formatted(), DeviceAuthorizationDecision.ALLOW));

        assertThat(deviceCode.status()).isEqualTo(DeviceCodeStatus.APPROVED);
        assertThat(deviceCode.userId()).isEqualTo(USER_ID);
        verify(deviceCodeRepository).save(deviceCode);
    }

    @Test
    void denyingAPendingCodeMarksItDeniedAndSavesIt() {
        UserCode userCode = UserCode.generate();
        DeviceCode deviceCode = pendingDeviceCodeFor(userCode, TENANT_ID);
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));
        when(deviceCodeRepository.save(any(DeviceCode.class))).thenAnswer(invocation -> invocation.getArgument(0));

        useCase.execute(command(userCode.formatted(), DeviceAuthorizationDecision.DENY));

        assertThat(deviceCode.status()).isEqualTo(DeviceCodeStatus.DENIED);
        verify(deviceCodeRepository).save(deviceCode);
    }

    @Test
    void rejectsAMalformedUserCode() {
        assertThatThrownBy(() -> useCase.execute(command("!!!", DeviceAuthorizationDecision.ALLOW)))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
        verify(deviceCodeRepository, never()).findByUserCode(any());
    }

    @Test
    void rejectsAUserCodeThatDoesNotExist() {
        UserCode userCode = UserCode.generate();
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(command(userCode.formatted(), DeviceAuthorizationDecision.ALLOW)))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
        verify(deviceCodeRepository, never()).save(any());
    }

    @Test
    void rejectsAUserCodeBelongingToAnotherTenant() {
        UserCode userCode = UserCode.generate();
        DeviceCode deviceCode = pendingDeviceCodeFor(userCode, OTHER_TENANT_ID);
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));

        assertThatThrownBy(() -> useCase.execute(command(userCode.formatted(), DeviceAuthorizationDecision.ALLOW)))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
        verify(deviceCodeRepository, never()).save(any());
    }

    @Test
    void rejectsApprovingACodeThatWasAlreadyDecided() {
        UserCode userCode = UserCode.generate();
        DeviceCode deviceCode = pendingDeviceCodeFor(userCode, TENANT_ID);
        deviceCode.deny(Instant.now());
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));

        assertThatThrownBy(() -> useCase.execute(command(userCode.formatted(), DeviceAuthorizationDecision.ALLOW)))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
        verify(deviceCodeRepository, never()).save(any());
    }

    @Test
    void rejectsDenyingACodeThatWasAlreadyApproved() {
        UserCode userCode = UserCode.generate();
        DeviceCode deviceCode = pendingDeviceCodeFor(userCode, TENANT_ID);
        deviceCode.approve(UserId.generate(), Instant.now());
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));

        assertThatThrownBy(() -> useCase.execute(command(userCode.formatted(), DeviceAuthorizationDecision.DENY)))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
        verify(deviceCodeRepository, never()).save(any());
    }

    @Test
    void rejectsDecidingAnExpiredCode() {
        UserCode userCode = UserCode.generate();
        DeviceCode deviceCode = DeviceCode.request(
                TENANT_ID,
                CLIENT_ID,
                TokenHash.of("device-code-hash"),
                userCode,
                Set.of("openid"),
                Instant.now().minus(Duration.ofMinutes(20)),
                Duration.ofMinutes(10));
        when(deviceCodeRepository.findByUserCode(userCode)).thenReturn(Optional.of(deviceCode));

        assertThatThrownBy(() -> useCase.execute(command(userCode.formatted(), DeviceAuthorizationDecision.ALLOW)))
                .isInstanceOf(DeviceAuthorizationNotFoundException.class);
        verify(deviceCodeRepository, never()).save(any());
    }
}
