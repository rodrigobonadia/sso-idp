package com.ssoplatform.idp.application.usecase.device;

import com.ssoplatform.idp.application.exception.DeviceAuthorizationNotFoundException;
import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.DeviceCodeStateException;
import com.ssoplatform.idp.domain.devicecode.InvalidUserCodeException;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Instant;
import java.util.Objects;

/**
 * Handles the verification page's decision step ({@code POST /device/allow} or {@code POST
 * /device/deny}): applies the already-authenticated user's Allow/Deny choice to the device code
 * {@link FindDeviceAuthorizationUseCase} already confirmed exists and is pending.
 *
 * <p>Re-resolves the code from {@code user_code} rather than trusting a hidden form field carrying
 * an internal id straight through from the previous request - the same "never trust a client-
 * supplied identifier without re-validating it" posture {@code TokenUseCase} takes with every
 * grant. {@link DeviceCode#approve}/{@link DeviceCode#deny} throw {@link DeviceCodeStateException}
 * or {@link VerificationTokenExpiredException} if the code was decided or expired in the moments
 * between the two requests (a real, if narrow, race) - both are reported identically via {@link
 * DeviceAuthorizationNotFoundException}, exactly like a not-found code, for the same enumeration-
 * safety reasoning.
 */
public class DecideDeviceAuthorizationUseCase {

    private final DeviceCodeRepository deviceCodeRepository;

    public DecideDeviceAuthorizationUseCase(DeviceCodeRepository deviceCodeRepository) {
        this.deviceCodeRepository =
                Objects.requireNonNull(deviceCodeRepository, "deviceCodeRepository must not be null");
    }

    public void execute(DecideDeviceAuthorizationCommand command) {
        Objects.requireNonNull(command, "command must not be null");
        TenantId tenantId = TenantId.of(command.tenantId());

        UserCode userCode;
        try {
            userCode = UserCode.of(command.rawUserCode());
        } catch (InvalidUserCodeException ex) {
            throw new DeviceAuthorizationNotFoundException();
        }

        DeviceCode deviceCode = deviceCodeRepository
                .findByUserCode(userCode)
                .filter(candidate -> candidate.tenantId().equals(tenantId))
                .orElseThrow(DeviceAuthorizationNotFoundException::new);

        Instant now = Instant.now();
        try {
            switch (command.decision()) {
                case ALLOW -> deviceCode.approve(UserId.of(command.userId()), now);
                case DENY -> deviceCode.deny(now);
            }
        } catch (DeviceCodeStateException | VerificationTokenExpiredException ex) {
            throw new DeviceAuthorizationNotFoundException();
        }

        deviceCodeRepository.save(deviceCode);
    }
}
