package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.port.out.VerificationTokenRepository;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.EmailVerificationToken;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Instant;
import java.util.Objects;

/**
 * Confirms a user's e-mail address from the token they were sent.
 *
 * <p>The raw token is hashed and looked up by hash - never by scanning stored tokens for a
 * plaintext match, since only the hash is ever persisted (see {@link EmailVerificationToken}).
 * The token is consumed before the user record is touched, so a token that fails its own
 * invariants (already used, expired) never ends up activating an account.
 *
 * <p>{@link UserNotFoundException} here is a defensive/should-never-happen guard: a valid,
 * unconsumed token's {@code userId} always refers to a real user, since users and their tokens
 * are created together by {@link RegisterUserUseCase}.
 */
public class VerifyEmailUseCase {

    private final VerificationTokenRepository verificationTokenRepository;
    private final VerificationTokenHasher verificationTokenHasher;
    private final UserRepository userRepository;

    public VerifyEmailUseCase(
            VerificationTokenRepository verificationTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            UserRepository userRepository) {
        this.verificationTokenRepository =
                Objects.requireNonNull(verificationTokenRepository, "verificationTokenRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
    }

    public VerifyEmailResult execute(VerifyEmailCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        RawVerificationToken rawToken = RawVerificationToken.of(command.rawToken());
        TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
        EmailVerificationToken token = verificationTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(VerificationTokenNotFoundException::new);

        token.consume(Instant.now());
        verificationTokenRepository.save(token);

        User user = userRepository
                .findById(token.userId())
                .orElseThrow(() -> new UserNotFoundException(token.userId().value()));
        user.verifyEmail();
        User saved = userRepository.save(user);

        return new VerifyEmailResult(saved.id().value(), saved.email().value());
    }
}
