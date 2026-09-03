package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.List;

/**
 * Output port for {@link RecoveryCode} persistence, always scoped by {@link UserId}.
 *
 * <p>{@link #findUnconsumedByUserId} - not a hash-equality lookup - because {@link
 * com.ssoplatform.idp.domain.mfa.RecoveryCodeHash} values are salted (BCrypt): the only way to
 * check a candidate code is to load every unconsumed code for the user and try {@code
 * RecoveryCodeHasher#matches} against each one in turn.
 */
public interface RecoveryCodeRepository {

    List<RecoveryCode> saveAll(List<RecoveryCode> codes);

    RecoveryCode save(RecoveryCode code);

    List<RecoveryCode> findUnconsumedByUserId(UserId userId);

    void deleteAllByUserId(UserId userId);
}
