package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Optional;

/**
 * Output port for {@link DeviceCode} persistence. Looked up two different ways for two different
 * callers: {@link #findByDeviceCodeHash} by the polling device presenting its raw {@code
 * device_code} at {@code /token} (mirroring {@code AuthorizationCodeRepository#findByCodeHash}),
 * and {@link #findByUserCode} by a human at the verification page typing in the low-entropy {@code
 * user_code} - see {@code UserCode}'s Javadoc for why the two need such different lookup keys.
 *
 * <p>{@link #findByUserCode} deliberately has no status/expiry filter of its own - every caller
 * (uniqueness checks at issuance, the verification page lookup) is expected to apply whatever
 * status/expiry rule it needs on the returned {@link DeviceCode} itself, exactly like {@code
 * AuthorizationCodeRepository#findByCodeHash} does.
 */
public interface DeviceCodeRepository {

    DeviceCode save(DeviceCode deviceCode);

    Optional<DeviceCode> findByDeviceCodeHash(TokenHash deviceCodeHash);

    Optional<DeviceCode> findByUserCode(UserCode userCode);
}
