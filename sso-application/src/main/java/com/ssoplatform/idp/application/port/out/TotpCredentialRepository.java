package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Optional;

/** Output port for {@link TotpCredential} persistence - looked up only by {@link UserId}, since
 * exactly one credential (pending or active) can exist per user at a time. */
public interface TotpCredentialRepository {

    TotpCredential save(TotpCredential credential);

    Optional<TotpCredential> findByUserId(UserId userId);

    void deleteByUserId(UserId userId);
}
