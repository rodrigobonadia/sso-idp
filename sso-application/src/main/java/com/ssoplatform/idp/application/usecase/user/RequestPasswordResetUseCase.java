package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.PasswordResetTokenRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.InvalidEmailException;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserStatus;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Starts the "forgot my password" flow: if the given tenant-scoped e-mail matches a real,
 * self-service-eligible account, issues a single-use reset token and e-mails it.
 *
 * <p>Deliberately enumeration-safe in the same spirit as {@code LoginUseCase}, but mirrored: where
 * a login attempt always <em>fails</em> the same generic way regardless of whether the e-mail is
 * registered, this use case always <em>succeeds</em> the same way (returns normally, throws
 * nothing) whether or not the e-mail matches an account, whether the e-mail is malformed, and
 * regardless of that account's status - a caller watching only this method's outcome can never
 * distinguish "no such account" from "an account exists but couldn't be sent a token", so nothing
 * here can be used to probe which e-mail addresses are registered. The one exception is a {@code
 * DISABLED} account: no token is issued for one, since a disabled account can never successfully
 * complete a reset anyway ({@code User.changePassword} rejects it) - this is purely an
 * efficiency/no-dangling-token choice, not a behavior a caller can observe from outside.
 */
public class RequestPasswordResetUseCase {

    /** How long a freshly issued password-reset token remains valid - shorter than the 24h e-mail
     * verification token, since resetting a password is a more sensitive action. */
    static final Duration RESET_TOKEN_VALIDITY = Duration.ofHours(1);

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final VerificationTokenHasher verificationTokenHasher;
    private final EmailSender emailSender;

    public RequestPasswordResetUseCase(
            UserRepository userRepository,
            PasswordResetTokenRepository passwordResetTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            EmailSender emailSender) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.passwordResetTokenRepository =
                Objects.requireNonNull(passwordResetTokenRepository, "passwordResetTokenRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
        this.emailSender = Objects.requireNonNull(emailSender, "emailSender must not be null");
    }

    public void execute(RequestPasswordResetCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        TenantId tenantId = TenantId.of(command.tenantId());
        findEligibleUser(tenantId, command.email())
                .ifPresent(user -> issueAndSendToken(user, command.tenantSlug()));
    }

    private Optional<User> findEligibleUser(TenantId tenantId, String rawEmail) {
        try {
            Email email = Email.of(rawEmail);
            return userRepository
                    .findByTenantIdAndEmail(tenantId, email)
                    .filter(user -> user.status() != UserStatus.DISABLED);
        } catch (InvalidEmailException ex) {
            return Optional.empty();
        }
    }

    private void issueAndSendToken(User user, String tenantSlug) {
        RawVerificationToken rawToken = RawVerificationToken.generate();
        TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
        PasswordResetToken resetToken =
                PasswordResetToken.issue(user.id(), tokenHash, Instant.now(), RESET_TOKEN_VALIDITY);
        passwordResetTokenRepository.save(resetToken);

        emailSender.sendPasswordResetEmail(user.email(), tenantSlug, rawToken);
    }
}
