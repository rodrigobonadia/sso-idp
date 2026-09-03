package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.MfaAlreadyEnabledException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpSecretEncryptor;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Objects;

/**
 * Starts (or restarts) TOTP enrollment for an already-authenticated user: generates a brand-new
 * random secret, encrypts it at rest, and persists it as a {@code PENDING_ACTIVATION} credential -
 * unusable to satisfy a login challenge until {@link ConfirmTotpEnrollmentUseCase} proves the user
 * actually captured it correctly.
 *
 * <p>Refuses outright ({@link MfaAlreadyEnabledException}) if the user already has an ACTIVE
 * credential of EITHER method - since Phase 4.2, a user may have at most one active second factor
 * (TOTP or e-mail OTP) at a time; switching methods means disabling the current one first via
 * {@code DisableMfaUseCase}. A leftover {@code PENDING_ACTIVATION} TOTP credential from an
 * abandoned earlier attempt, by contrast, is freely replaced: it was never proven to work, so
 * there is nothing to protect by keeping it - see {@code phase_4_1_totp_mfa.md}.
 */
public class EnrollTotpUseCase {

    /** 160 bits - the secret length RFC 4226 recommends for HOTP/TOTP, and a multiple of 5 bits so
     * {@link Base32#encode} never needs padding. */
    static final int SECRET_BYTE_LENGTH = 20;

    private static final String ISSUER = "SSO IdP";

    private final UserRepository userRepository;
    private final TotpCredentialRepository totpCredentialRepository;
    private final EmailOtpCredentialRepository emailOtpCredentialRepository;
    private final TotpSecretEncryptor totpSecretEncryptor;

    public EnrollTotpUseCase(
            UserRepository userRepository,
            TotpCredentialRepository totpCredentialRepository,
            EmailOtpCredentialRepository emailOtpCredentialRepository,
            TotpSecretEncryptor totpSecretEncryptor) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.emailOtpCredentialRepository =
                Objects.requireNonNull(emailOtpCredentialRepository, "emailOtpCredentialRepository must not be null");
        this.totpSecretEncryptor =
                Objects.requireNonNull(totpSecretEncryptor, "totpSecretEncryptor must not be null");
    }

    public EnrollTotpResult execute(EnrollTotpCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        UserId userId = UserId.of(command.userId());
        User user = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(command.userId()));

        totpCredentialRepository
                .findByUserId(userId)
                .filter(TotpCredential::isActive)
                .ifPresent(credential -> {
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
        // per-user constraint) to simply replace it.
        totpCredentialRepository.deleteByUserId(userId);

        byte[] rawSecret = new byte[SECRET_BYTE_LENGTH];
        new SecureRandom().nextBytes(rawSecret);
        EncryptedTotpSecret encryptedSecret = totpSecretEncryptor.encrypt(rawSecret);

        TotpCredential credential = TotpCredential.enroll(userId, encryptedSecret, Instant.now());
        totpCredentialRepository.save(credential);

        String secretBase32 = Base32.encode(rawSecret);
        return new EnrollTotpResult(secretBase32, buildOtpauthUri(secretBase32, user.email().value()));
    }

    private static String buildOtpauthUri(String secretBase32, String accountEmail) {
        String encodedIssuer = urlEncode(ISSUER);
        String encodedLabel = urlEncode(ISSUER + ":" + accountEmail);
        return "otpauth://totp/" + encodedLabel
                + "?secret=" + secretBase32
                + "&issuer=" + encodedIssuer
                + "&algorithm=SHA1&digits=6&period=30";
    }

    private static String urlEncode(String value) {
        // URLEncoder is form-encoding (space -> '+'), not URI percent-encoding (space -> %20) -
        // otpauth:// consumers expect the latter.
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
