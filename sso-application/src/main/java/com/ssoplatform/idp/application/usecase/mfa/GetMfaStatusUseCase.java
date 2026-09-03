package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.MfaMethod;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Objects;

/**
 * Reports whether an already-authenticated user currently has MFA enabled, and with which method -
 * a pure read, backing the account settings page's "enable/disable" toggle. Since Phase 4.2, a
 * user may have at most one of TOTP/e-mail-OTP ACTIVE at a time (see {@code
 * EnableEmailOtpUseCase}/{@code EnrollTotpUseCase}), so checking both and finding at most one hit
 * is always well-defined.
 */
public class GetMfaStatusUseCase {

    private final TotpCredentialRepository totpCredentialRepository;
    private final EmailOtpCredentialRepository emailOtpCredentialRepository;

    public GetMfaStatusUseCase(
            TotpCredentialRepository totpCredentialRepository,
            EmailOtpCredentialRepository emailOtpCredentialRepository) {
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.emailOtpCredentialRepository =
                Objects.requireNonNull(emailOtpCredentialRepository, "emailOtpCredentialRepository must not be null");
    }

    public GetMfaStatusResult execute(GetMfaStatusQuery query) {
        Objects.requireNonNull(query, "query must not be null");
        UserId userId = UserId.of(query.userId());

        boolean totpActive =
                totpCredentialRepository.findByUserId(userId).map(TotpCredential::isActive).orElse(false);
        if (totpActive) {
            return new GetMfaStatusResult(true, MfaMethod.TOTP);
        }

        boolean emailOtpActive = emailOtpCredentialRepository
                .findByUserId(userId)
                .map(EmailOtpCredential::isActive)
                .orElse(false);
        if (emailOtpActive) {
            return new GetMfaStatusResult(true, MfaMethod.EMAIL_OTP);
        }

        return new GetMfaStatusResult(false, null);
    }
}
