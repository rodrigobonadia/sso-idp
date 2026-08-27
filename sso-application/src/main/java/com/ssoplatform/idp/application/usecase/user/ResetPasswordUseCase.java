package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.PasswordResetTokenRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.RawPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserStatus;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Instant;
import java.util.Objects;

/**
 * Completes the "forgot my password" flow from the token the user was e-mailed.
 *
 * <p>The raw token is hashed and looked up by hash - never by scanning stored tokens for a
 * plaintext match, since only the hash is ever persisted (see {@link PasswordResetToken}). The
 * token is consumed (and the consumption persisted) before the user's password is touched, so a
 * token that fails its own invariants (already used, expired) never ends up changing a password.
 *
 * <p>The new password goes through {@link RawPassword#of(String)} - unlike {@code LoginUseCase}'s
 * candidate password, this one is being SET, not checked against a stored hash, so the platform's
 * strength policy correctly applies here.
 *
 * <p>A {@code LOCKED} account is unlocked as part of a successful reset (resetting the failed-
 * login counter): proving e-mail ownership via the reset link is treated as sufficient evidence to
 * lift a lockout that was only ever a defensive, automatic measure - not an administrative
 * decision (that's {@code DISABLED}, which {@link User#changePassword} refuses outright,
 * surfacing as an unhandled {@code UserStateException} here).
 *
 * <p>{@link UserNotFoundException} here is a defensive/should-never-happen guard: a valid,
 * unconsumed token's {@code userId} always refers to a real user, since users and their tokens
 * are created together by {@link RequestPasswordResetUseCase}.
 */
public class ResetPasswordUseCase {

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final VerificationTokenHasher verificationTokenHasher;
    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;

    public ResetPasswordUseCase(
            PasswordResetTokenRepository passwordResetTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            UserRepository userRepository,
            PasswordHasher passwordHasher) {
        this.passwordResetTokenRepository =
                Objects.requireNonNull(passwordResetTokenRepository, "passwordResetTokenRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher must not be null");
    }

    public ResetPasswordResult execute(ResetPasswordCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        // Both inputs are validated in full BEFORE the token is looked up and consumed: a token is
        // single-use, so a submission that's going to be rejected anyway (a malformed token, a
        // weak new password) must never burn it - the user would otherwise have to request a
        // brand-new reset link just because of a typo, even though nothing was actually reset.
        RawVerificationToken rawToken = RawVerificationToken.of(command.rawToken());
        RawPassword newPassword = RawPassword.of(command.newRawPassword());

        TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
        PasswordResetToken token = passwordResetTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(VerificationTokenNotFoundException::new);

        token.consume(Instant.now());
        passwordResetTokenRepository.save(token);

        User user = userRepository
                .findById(token.userId())
                .orElseThrow(() -> new UserNotFoundException(token.userId().value()));

        HashedPassword newPasswordHash = passwordHasher.hash(newPassword);
        user.changePassword(newPasswordHash);
        if (user.status() == UserStatus.LOCKED) {
            user.unlock();
        }
        User saved = userRepository.save(user);

        return new ResetPasswordResult(saved.id().value(), saved.tenantId().value(), saved.email().value());
    }
}
