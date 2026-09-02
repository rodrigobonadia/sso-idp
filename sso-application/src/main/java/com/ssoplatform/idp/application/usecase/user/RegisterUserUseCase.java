package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.port.out.VerificationTokenRepository;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.EmailVerificationToken;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Registers a new user and kicks off e-mail verification.
 *
 * <p>Delegates account creation itself - tenant validation, e-mail uniqueness, password hashing -
 * to {@link CreateUserUseCase}, so the two use cases can never drift on what "creating a user"
 * means. This use case's own responsibility is exactly what comes after: issuing a single-use
 * verification token, persisting it, and dispatching it through {@link EmailSender}.
 */
public class RegisterUserUseCase {

    /** How long a freshly issued verification token remains valid. */
    static final Duration VERIFICATION_TOKEN_VALIDITY = Duration.ofHours(24);

    private final CreateUserUseCase createUserUseCase;
    private final VerificationTokenRepository verificationTokenRepository;
    private final VerificationTokenHasher verificationTokenHasher;
    private final EmailSender emailSender;

    public RegisterUserUseCase(
            CreateUserUseCase createUserUseCase,
            VerificationTokenRepository verificationTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            EmailSender emailSender) {
        this.createUserUseCase = Objects.requireNonNull(createUserUseCase, "createUserUseCase must not be null");
        this.verificationTokenRepository =
                Objects.requireNonNull(verificationTokenRepository, "verificationTokenRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
        this.emailSender = Objects.requireNonNull(emailSender, "emailSender must not be null");
    }

    public RegisterUserResult execute(RegisterUserCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        CreateUserResult created = createUserUseCase.execute(
                new CreateUserCommand(
                        command.tenantId(),
                        command.email(),
                        command.givenName(),
                        command.familyName(),
                        command.rawPassword()));

        RawVerificationToken rawToken = RawVerificationToken.generate();
        TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
        EmailVerificationToken verificationToken = EmailVerificationToken.issue(
                UserId.of(created.userId()), tokenHash, Instant.now(), VERIFICATION_TOKEN_VALIDITY);
        verificationTokenRepository.save(verificationToken);

        emailSender.sendVerificationEmail(Email.of(created.email()), command.tenantSlug(), rawToken);

        return new RegisterUserResult(created.userId(), created.tenantId(), created.email());
    }
}
