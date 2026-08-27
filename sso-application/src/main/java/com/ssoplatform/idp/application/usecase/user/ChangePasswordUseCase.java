package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.exception.IncorrectCurrentPasswordException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.RawPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.UserId;
import java.util.Objects;

/**
 * Changes the password of an already-authenticated user, given their current password.
 *
 * <p>The current password is compared as a plain {@code String} ({@link
 * PasswordHasher#matches(String, com.ssoplatform.idp.domain.user.HashedPassword)}), never through
 * {@link RawPassword#of(String)} - the exact same reasoning as {@code LoginUseCase}: that factory
 * enforces the platform's current strength policy, which is the right guard when a password is
 * being SET (the new password below), not when an existing one is merely being CHECKED. The new
 * password, by contrast, correctly goes through {@code RawPassword.of(...)}, since it is what will
 * actually be stored.
 *
 * <p>Unlike a wrong login password, a wrong current password here raises a specific {@link
 * IncorrectCurrentPasswordException} rather than a generic one: the caller already holds an
 * authenticated session for this exact user (see {@link ChangePasswordCommand}), so there is no
 * "which account" left to protect by staying vague.
 *
 * <p>{@link UserNotFoundException} here is a defensive/should-never-happen guard: {@code userId}
 * comes from an already-authenticated session, which can only exist for a user that was real at
 * login time.
 */
public class ChangePasswordUseCase {

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;

    public ChangePasswordUseCase(UserRepository userRepository, PasswordHasher passwordHasher) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher must not be null");
    }

    public ChangePasswordResult execute(ChangePasswordCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        User user = userRepository
                .findById(UserId.of(command.userId()))
                .orElseThrow(() -> new UserNotFoundException(command.userId()));

        if (!passwordHasher.matches(command.currentRawPassword(), user.passwordHash())) {
            throw new IncorrectCurrentPasswordException();
        }

        RawPassword newPassword = RawPassword.of(command.newRawPassword());
        HashedPassword newPasswordHash = passwordHasher.hash(newPassword);
        user.changePassword(newPasswordHash);
        User saved = userRepository.save(user);

        return new ChangePasswordResult(saved.id().value(), saved.email().value());
    }
}
