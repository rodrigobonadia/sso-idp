package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.MfaEnrollmentNotFoundException;
import com.ssoplatform.idp.application.port.out.RecoveryCodeHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.application.port.out.TotpCodeVerifier;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpSecretEncryptor;
import com.ssoplatform.idp.domain.mfa.RawRecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import com.ssoplatform.idp.domain.mfa.TotpCode;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Completes TOTP enrollment: the user must prove their authenticator app was set up correctly by
 * submitting a real, currently valid code before the pending credential becomes usable to satisfy
 * a login challenge - see {@link EnrollTotpUseCase}'s Javadoc for why this two-step shape exists.
 *
 * <p>On success, also generates and persists a brand-new batch of ten single-use recovery codes
 * (replacing any codes left over from a previous enrollment cycle) and returns them in plaintext -
 * the only moment they ever exist outside their {@link RecoveryCodeHash} form. The caller (API
 * layer) is responsible for showing these to the user exactly once.
 */
public class ConfirmTotpEnrollmentUseCase {

    static final int RECOVERY_CODE_COUNT = 10;

    private final TotpCredentialRepository totpCredentialRepository;
    private final TotpSecretEncryptor totpSecretEncryptor;
    private final TotpCodeVerifier totpCodeVerifier;
    private final RecoveryCodeRepository recoveryCodeRepository;
    private final RecoveryCodeHasher recoveryCodeHasher;

    public ConfirmTotpEnrollmentUseCase(
            TotpCredentialRepository totpCredentialRepository,
            TotpSecretEncryptor totpSecretEncryptor,
            TotpCodeVerifier totpCodeVerifier,
            RecoveryCodeRepository recoveryCodeRepository,
            RecoveryCodeHasher recoveryCodeHasher) {
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.totpSecretEncryptor =
                Objects.requireNonNull(totpSecretEncryptor, "totpSecretEncryptor must not be null");
        this.totpCodeVerifier = Objects.requireNonNull(totpCodeVerifier, "totpCodeVerifier must not be null");
        this.recoveryCodeRepository =
                Objects.requireNonNull(recoveryCodeRepository, "recoveryCodeRepository must not be null");
        this.recoveryCodeHasher = Objects.requireNonNull(recoveryCodeHasher, "recoveryCodeHasher must not be null");
    }

    public ConfirmTotpEnrollmentResult execute(ConfirmTotpEnrollmentCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        UserId userId = UserId.of(command.userId());
        TotpCredential credential = totpCredentialRepository
                .findByUserId(userId)
                .filter(c -> !c.isActive())
                .orElseThrow(MfaEnrollmentNotFoundException::new);

        TotpCode code = TotpCode.of(command.code());
        byte[] rawSecret = totpSecretEncryptor.decrypt(credential.encryptedSecret());
        if (!totpCodeVerifier.verify(rawSecret, code)) {
            throw new InvalidMfaCodeException();
        }

        credential.activate(Instant.now());
        totpCredentialRepository.save(credential);

        return new ConfirmTotpEnrollmentResult(issueRecoveryCodes(userId));
    }

    private List<String> issueRecoveryCodes(UserId userId) {
        recoveryCodeRepository.deleteAllByUserId(userId);

        List<String> rawCodes = new ArrayList<>(RECOVERY_CODE_COUNT);
        List<RecoveryCode> toSave = new ArrayList<>(RECOVERY_CODE_COUNT);
        Instant now = Instant.now();
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            RawRecoveryCode raw = RawRecoveryCode.generate();
            RecoveryCodeHash hash = recoveryCodeHasher.hash(raw);
            toSave.add(RecoveryCode.issue(userId, hash, now));
            rawCodes.add(raw.value());
        }
        recoveryCodeRepository.saveAll(toSave);
        return rawCodes;
    }
}
