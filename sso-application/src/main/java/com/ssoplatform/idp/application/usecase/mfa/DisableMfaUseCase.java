package com.ssoplatform.idp.application.usecase.mfa;

import com.ssoplatform.idp.application.exception.IncorrectCurrentPasswordException;
import com.ssoplatform.idp.application.exception.MfaNotEnabledException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Objects;

/**
 * Turns MFA off for an already-authenticated user (and, incidentally, cancels an unconfirmed
 * enrollment the same way - there is no separate "cancel enrollment" action, since discarding a
 * pending credential and disabling an active one are the same operation from this use case's
 * point of view).
 *
 * <p>Requires the caller's current password as re-authentication evidence, exactly like {@code
 * ChangePasswordUseCase} - disabling a second factor is sensitive enough that merely holding an
 * existing session must not be sufficient on its own (a hijacked, already-logged-in session could
 * otherwise strip MFA protection silently).
 *
 * <p>A hard delete, not a status transition: unlike a revoked refresh token or a retired signing
 * key, there is no audit or verification value in keeping a disabled TOTP secret or spent recovery
 * codes around - see {@code TotpCredentialStatus}'s Javadoc.
 */
public class DisableMfaUseCase {

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TotpCredentialRepository totpCredentialRepository;
    private final RecoveryCodeRepository recoveryCodeRepository;

    public DisableMfaUseCase(
            UserRepository userRepository,
            PasswordHasher passwordHasher,
            TotpCredentialRepository totpCredentialRepository,
            RecoveryCodeRepository recoveryCodeRepository) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher must not be null");
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.recoveryCodeRepository =
                Objects.requireNonNull(recoveryCodeRepository, "recoveryCodeRepository must not be null");
    }

    public void execute(DisableMfaCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        UserId userId = UserId.of(command.userId());
        User user = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(command.userId()));

        if (!passwordHasher.matches(command.currentRawPassword(), user.passwordHash())) {
            throw new IncorrectCurrentPasswordException();
        }

        totpCredentialRepository.findByUserId(userId).orElseThrow(MfaNotEnabledException::new);

        totpCredentialRepository.deleteByUserId(userId);
        recoveryCodeRepository.deleteAllByUserId(userId);
    }
}
