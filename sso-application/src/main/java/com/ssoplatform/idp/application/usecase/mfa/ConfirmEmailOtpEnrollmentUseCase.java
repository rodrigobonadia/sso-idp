package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.MfaEnrollmentNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.RecoveryCodeHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;
import com.ssoplatform.idp.domain.mfa.RawRecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Completes e-mail OTP enrollment: the user must prove they received a real, currently valid code
 * at their registered address before the pending credential becomes usable to satisfy a login
 * challenge - see {@link EnableEmailOtpUseCase}'s Javadoc for why this two-step shape exists.
 *
 * <p>A wrong code counts against {@link EmailOtpCode#MAX_FAILED_ATTEMPTS} (see that class's
 * Javadoc for why an e-mailed code needs this, unlike a TOTP confirmation which is time-windowed
 * on its own) - once exceeded, the code is dead and the user must request a fresh one by calling
 * {@link EnableEmailOtpUseCase} again.
 *
 * <p>Mirrors {@link ConfirmTotpEnrollmentUseCase} exactly for the recovery-code side effect: on
 * success, also generates and persists a brand-new batch of ten single-use recovery codes
 * (replacing any left over from a previous enrollment cycle, regardless of which method that cycle
 * used - recovery codes are method-agnostic) and returns them in plaintext.
 */
public class ConfirmEmailOtpEnrollmentUseCase {

    static final int RECOVERY_CODE_COUNT = 10;

    private final EmailOtpCredentialRepository emailOtpCredentialRepository;
    private final EmailOtpCodeRepository emailOtpCodeRepository;
    private final EmailOtpCodeHasher emailOtpCodeHasher;
    private final RecoveryCodeRepository recoveryCodeRepository;
    private final RecoveryCodeHasher recoveryCodeHasher;

    public ConfirmEmailOtpEnrollmentUseCase(
            EmailOtpCredentialRepository emailOtpCredentialRepository,
            EmailOtpCodeRepository emailOtpCodeRepository,
            EmailOtpCodeHasher emailOtpCodeHasher,
            RecoveryCodeRepository recoveryCodeRepository,
            RecoveryCodeHasher recoveryCodeHasher) {
        this.emailOtpCredentialRepository =
                Objects.requireNonNull(emailOtpCredentialRepository, "emailOtpCredentialRepository must not be null");
        this.emailOtpCodeRepository =
                Objects.requireNonNull(emailOtpCodeRepository, "emailOtpCodeRepository must not be null");
        this.emailOtpCodeHasher = Objects.requireNonNull(emailOtpCodeHasher, "emailOtpCodeHasher must not be null");
        this.recoveryCodeRepository =
                Objects.requireNonNull(recoveryCodeRepository, "recoveryCodeRepository must not be null");
        this.recoveryCodeHasher = Objects.requireNonNull(recoveryCodeHasher, "recoveryCodeHasher must not be null");
    }

    public ConfirmEmailOtpEnrollmentResult execute(ConfirmEmailOtpEnrollmentCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        UserId userId = UserId.of(command.userId());
        EmailOtpCredential credential = emailOtpCredentialRepository
                .findByUserId(userId)
                .filter(c -> !c.isActive())
                .orElseThrow(MfaEnrollmentNotFoundException::new);

        EmailOtpCode code = emailOtpCodeRepository
                .findLatestByUserIdAndPurpose(userId, EmailOtpPurpose.ENROLLMENT_CONFIRMATION)
                .orElseThrow(MfaEnrollmentNotFoundException::new);

        RawEmailOtpCode candidate = RawEmailOtpCode.of(command.code());
        Instant now = Instant.now();
        if (!emailOtpCodeHasher.matches(candidate, code.codeHash())) {
            code.recordFailedAttempt(now);
            emailOtpCodeRepository.save(code);
            throw new InvalidMfaCodeException();
        }
        code.consume(now);
        emailOtpCodeRepository.save(code);

        credential.activate(now);
        emailOtpCredentialRepository.save(credential);

        return new ConfirmEmailOtpEnrollmentResult(issueRecoveryCodes(userId));
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
