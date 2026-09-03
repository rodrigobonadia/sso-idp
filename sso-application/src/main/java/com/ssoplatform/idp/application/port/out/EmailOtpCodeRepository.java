package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.domain.mfa.MfaChallengeId;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Optional;

/** Output port for {@link EmailOtpCode} persistence. */
public interface EmailOtpCodeRepository {

    EmailOtpCode save(EmailOtpCode code);

    /** Looks up the code tied to one specific login challenge - unambiguous by construction,
     * since exactly one {@link EmailOtpCode} is ever issued per {@code MfaChallenge}. */
    Optional<EmailOtpCode> findByMfaChallengeId(MfaChallengeId mfaChallengeId);

    /** Looks up the most recently issued code for a user/purpose - used only for {@link
     * EmailOtpPurpose#ENROLLMENT_CONFIRMATION} (which, unlike a login challenge, has no single
     * unique correlation id to look up by instead). */
    Optional<EmailOtpCode> findLatestByUserIdAndPurpose(UserId userId, EmailOtpPurpose purpose);

    /**
     * Hard-deletes every row for a user/purpose - used to invalidate a still-live enrollment
     * confirmation code the moment a fresh one is issued (re-enabling over a still-pending
     * credential), so an older, possibly-intercepted code can never still be accepted. A derived
     * delete query - MUST carry an explicit {@code @Transactional} on whichever adapter implements
     * this, exactly like {@code TotpCredentialRepository#deleteByUserId} (Phase 4.1's real bug).
     */
    void deleteByUserIdAndPurpose(UserId userId, EmailOtpPurpose purpose);
}
