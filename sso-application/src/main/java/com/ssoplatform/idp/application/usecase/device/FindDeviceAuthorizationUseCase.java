package com.ssoplatform.idp.application.usecase.device;

import com.ssoplatform.idp.application.exception.DeviceAuthorizationNotFoundException;
import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.DeviceCodeStatus;
import com.ssoplatform.idp.domain.devicecode.InvalidUserCodeException;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import java.util.Objects;

/**
 * Handles the verification page's lookup step ({@code POST /device} in this platform's flow): a
 * human typed in a {@code user_code}, and this resolves it to the {@link DeviceCode} they mean to
 * act on - if, and only if, it is in THIS tenant, still {@link DeviceCodeStatus#PENDING}, and
 * unexpired. Every other outcome (malformed code, no such code, wrong tenant, already decided,
 * expired) is collapsed into the single {@link DeviceAuthorizationNotFoundException} - see that
 * exception's Javadoc for why.
 */
public class FindDeviceAuthorizationUseCase {

    private final DeviceCodeRepository deviceCodeRepository;
    private final OAuthClientRepository oauthClientRepository;

    public FindDeviceAuthorizationUseCase(
            DeviceCodeRepository deviceCodeRepository, OAuthClientRepository oauthClientRepository) {
        this.deviceCodeRepository =
                Objects.requireNonNull(deviceCodeRepository, "deviceCodeRepository must not be null");
        this.oauthClientRepository =
                Objects.requireNonNull(oauthClientRepository, "oauthClientRepository must not be null");
    }

    public DeviceAuthorizationView execute(FindDeviceAuthorizationCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());

        DeviceCode deviceCode = resolvePendingDeviceCode(command.rawUserCode(), tenantId);

        OAuthClient client = oauthClientRepository
                .findById(deviceCode.oauthClientId())
                .orElseThrow(DeviceAuthorizationNotFoundException::new);

        return new DeviceAuthorizationView(deviceCode.userCode().formatted(), client.name());
    }

    private DeviceCode resolvePendingDeviceCode(String rawUserCode, TenantId tenantId) {
        UserCode userCode;
        try {
            userCode = UserCode.of(rawUserCode);
        } catch (InvalidUserCodeException ex) {
            throw new DeviceAuthorizationNotFoundException();
        }

        return deviceCodeRepository
                .findByUserCode(userCode)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .filter(candidate -> candidate.status() == DeviceCodeStatus.PENDING)
                .filter(candidate -> !candidate.isExpired(Instant.now()))
                .orElseThrow(DeviceAuthorizationNotFoundException::new);
    }
}
