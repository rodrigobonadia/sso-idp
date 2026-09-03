package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.MfaAlreadyEnabledException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EmailOtpPurpose;
import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Starts (or restarts) e-mail OTP enrollment for an already-authenticated user: creates a
 * {@code PENDING_ACTIVATION} {@link EmailOtpCredential} and immediately sends a confirmation code
 * to the user's own registered (already verified-at-registration) address - unusable to satisfy a
 * login challenge until {@link ConfirmEmailOtpEnrollmentUseCase} proves the user actually received
 * and typed it back correctly. See {@link EmailOtpCredential}'s Javadoc for why this two-step shape
 * matters even more here than for TOTP.
 *
 * <p>Refuses outright ({@link MfaAlreadyEnabledException}) if the user already has an ACTIVE
 * credential of EITHER method - a user may have at most one active second factor at a time (see
 * {@code phase_4_2_email_otp_mfa.md}); switching methods means disabling the current one first via
 * {@code DisableMfaUseCase}. A leftover {@code PENDING_ACTIVATION} e-mail-OTP credential from an
 * abandoned earlier attempt, by contrast, is freely replaced, exactly like {@code
 * EnrollTotpUseCase} - and re-running this use case while already PENDING is also how a user
 * requests a fresh code if the first one was lost or expired ("resend" needs no separate action):
 * any earlier still-live {@link EmailOtpPurpose#ENROLLMENT_CONFIRMATION} code is explicitly deleted
 * first, so an older, possibly-intercepted code can never still be accepted afterwards.
 */
public class EnableEmailOtpUseCase {

    /** Mirrors {@code LoginUseCase.MFA_CHALLENGE_VALIDITY} - see {@code EmailOtpCode}'s Javadoc for
     * why an e-mailed code's window matters and why 5 minutes is the deliberate, simple, single
     * shared duration for every e-mail-OTP code this system ever issues, enrollment or login. */
    static final Duration CODE_VALIDITY = Duration.ofMinutes(5);

    private final UserRepository userRepository;
    private final EmailOtpCredentialRepository emailOtpCredentialRepository;
    private final TotpCredentialRepository totpCredentialRepository;
    private final EmailOtpCodeRepository emailOtpCodeRepository;
    private final EmailOtpCodeHasher emailOtpCodeHasher;
    private final EmailSender emailSender;

    public EnableEmailOtpUseCase(
            UserRepository userRepository,
            EmailOtpCredentialRepository emailOtpCredentialRepository,
            TotpCredentialRepository totpCredentialRepository,
            EmailOtpCodeRepository emailOtpCodeRepository,
            EmailOtpCodeHasher emailOtpCodeHasher,
            EmailSender emailSender) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.emailOtpCredentialRepository =
                Objects.requireNonNull(emailOtpCredentialRepository, "emailOtpCredentialRepository must not be null");
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.emailOtpCodeRepository =
                Objects.requireNonNull(emailOtpCodeRepository, "emailOtpCodeRepository must not be null");
        this.emailOtpCodeHasher = Objects.requireNonNull(emailOtpCodeHasher, "emailOtpCodeHasher must not be null");
        this.emailSender = Objects.requireNonNull(emailSender, "emailSender must not be null");
    }

    public EnableEmailOtpResult execute(EnableEmailOtpCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        UserId userId = UserId.of(command.userId());
        User user = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(command.userId()));

        totpCredentialRepository.findByUserId(userId).filter(TotpCredential::isActive).ifPresent(credential -> {
            throw new MfaAlreadyEnabledException();
        });
        emailOtpCredentialRepository
                .findByUserId(userId)
                .filter(EmailOtpCredential::isActive)
                .ifPresent(credential -> {
                    throw new MfaAlreadyEnabledException();
                });
        // Any remaining credential here is a PENDING_ACTIVATION leftover from an abandoned
        // attempt - never proven to work, so it is safe (and necessary, to satisfy the one-row-
        // per-user constraint) to simply replace it, exactly like EnrollTotpUseCase.
        emailOtpCredentialRepository.deleteByUserId(userId);
        // Same reasoning for any still-live confirmation code from that abandoned attempt - see
        // this class's Javadoc for why this also doubles as the "resend" mechanism.
        emailOtpCodeRepository.deleteByUserIdAndPurpose(userId, EmailOtpPurpose.ENROLLMENT_CONFIRMATION);

        EmailOtpCredential credential = EmailOtpCredential.enable(userId, Instant.now());
        emailOtpCredentialRepository.save(credential);

        sendConfirmationCode(userId, user.email());

        return new EnableEmailOtpResult(maskEmail(user.email()));
    }

    private void sendConfirmationCode(UserId userId, Email email) {
        RawEmailOtpCode rawCode = RawEmailOtpCode.generate();
        EmailOtpCodeHash codeHash = emailOtpCodeHasher.hash(rawCode);
        EmailOtpCode code = EmailOtpCode.issueForEnrollment(userId, codeHash, Instant.now(), CODE_VALIDITY);
        emailOtpCodeRepository.save(code);
        emailSender.sendMfaEmailOtpCode(email, rawCode);
    }

    /** Masks the local part of an e-mail address for display (e.g. {@code "j***n@example.com"}),
     * so the confirmation screen can reassure the user which address a code was sent to without
     * fully re-disclosing it - the same nicety real providers (Google, GitHub, ...) offer. */
    private static String maskEmail(Email email) {
        String value = email.value();
        int at = value.indexOf('@');
        String local = value.substring(0, at);
        String domain = value.substring(at);
        String maskedLocal = local.length() <= 2
                ? local.charAt(0) + "***"
                : local.charAt(0) + "***" + local.charAt(local.length() - 1);
        return maskedLocal + domain;
    }
}
