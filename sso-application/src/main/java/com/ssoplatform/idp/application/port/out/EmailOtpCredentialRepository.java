package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Optional;

/** Output port for {@link EmailOtpCredential} persistence. Mirrors {@code TotpCredentialRepository}
 * exactly - at most one row per user, looked up and replaced the same way. */
public interface EmailOtpCredentialRepository {

    EmailOtpCredential save(EmailOtpCredential credential);

    Optional<EmailOtpCredential> findByUserId(UserId userId);

    /**
     * Hard-deletes the user's row, if any. A derived delete query - MUST carry an explicit
     * {@code @Transactional} on whichever adapter implements this, exactly like {@code
     * TotpCredentialRepository#deleteByUserId} - see that port's adapter for the real bug this
     * lesson was learned from in Phase 4.1.
     */
    void deleteByUserId(UserId userId);
}
