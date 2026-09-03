package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Objects;

/** Reports whether an already-authenticated user currently has MFA enabled - a pure read, backing
 * the account settings page's "enable/disable" toggle. */
public class GetMfaStatusUseCase {

    private final TotpCredentialRepository totpCredentialRepository;

    public GetMfaStatusUseCase(TotpCredentialRepository totpCredentialRepository) {
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
    }

    public GetMfaStatusResult execute(GetMfaStatusQuery query) {
        Objects.requireNonNull(query, "query must not be null");
        UserId userId = UserId.of(query.userId());
        boolean enabled = totpCredentialRepository.findByUserId(userId).map(TotpCredential::isActive).orElse(false);
        return new GetMfaStatusResult(enabled);
    }
}
