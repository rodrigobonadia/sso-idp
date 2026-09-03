package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.exception.AccountDisabledException;
import com.ssoplatform.idp.application.exception.AccountLockedException;
import com.ssoplatform.idp.application.exception.AccountNotVerifiedException;
import com.ssoplatform.idp.application.exception.InvalidCredentialsException;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
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

/**
 * Authenticates a user by tenant-scoped e-mail and password.
 *
 * <p>All real authentication logic lives here rather than in a framework abstraction (Spring
 * Security's {@code UserDetailsService}/{@code AuthenticationProvider} assume a single global
 * username namespace, whereas this system's uniqueness is per tenant), so the web layer's only
 * job after calling this use case is to establish the HTTP session for the returned identity - or,
 * since Phase 4.1, to walk the caller through an MFA challenge first (see {@link LoginOutcome}).
 *
 * <p>Ordering is deliberately security-conscious: the password is checked BEFORE the account
 * status, and a wrong password always raises the exact same {@link InvalidCredentialsException}
 * regardless of whether the e-mail exists at all for the tenant. This means status-specific
 * errors ({@link AccountNotVerifiedException}, {@link AccountLockedException}, {@link
 * AccountDisabledException}) only ever reach a caller who has already proven they know the
 * correct password - an attacker submitting wrong passwords can never use the error shape to
 * enumerate which e-mails are registered, verified, locked, or disabled. The MFA check happens
 * last of all, after the password AND the account status have both already been validated - a
 * caller learns "this account requires a second factor" only once they have proven everything
 * else about their claim to it.
 *
 * <p>The candidate password is compared as a plain {@code String} ({@link
 * PasswordHasher#matches(String, com.ssoplatform.idp.domain.user.HashedPassword)}), never through
 * {@link com.ssoplatform.idp.domain.user.RawPassword#of(String)}: that factory enforces the
 * platform's current strength policy, which is the right guard when a password is being SET
 * (registration, change-password) but wrong when a password is being CHECKED - a login attempt
 * that happens to be short or missing a character class is simply a wrong password, and must fail
 * the exact same generic way any other wrong password does, not with a policy-shaped error that
 * would both leak information and wrongly lock out a real user whose genuine password predates a
 * later policy tightening. The tenant-scoped e-mail lookup has the same shape: a malformed e-mail
 * can never match a real account, so it collapses into the same {@link InvalidCredentialsException}
 * rather than surfacing a distinct validation error.
 */
public class LoginUseCase {

    /** How long a freshly issued MFA challenge remains valid - see {@link MfaChallenge}'s Javadoc
     * for why this is much shorter than a password-reset token. */
    static final Duration MFA_CHALLENGE_VALIDITY = Duration.ofMinutes(5);

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TotpCredentialRepository totpCredentialRepository;
    private final MfaChallengeRepository mfaChallengeRepository;
    private final VerificationTokenHasher verificationTokenHasher;

    public LoginUseCase(
            UserRepository userRepository,
            PasswordHasher passwordHasher,
            TotpCredentialRepository totpCredentialRepository,
            MfaChallengeRepository mfaChallengeRepository,
            VerificationTokenHasher verificationTokenHasher) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher must not be null");
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.mfaChallengeRepository =
                Objects.requireNonNull(mfaChallengeRepository, "mfaChallengeRepository must not be null");
        this.verificationTokenHasher =
                Objects.requireNonNull(verificationTokenHasher, "verificationTokenHasher must not be null");
    }

    public LoginOutcome execute(LoginCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        TenantId tenantId = TenantId.of(command.tenantId());
        User user = findUserOrFail(tenantId, command.email());

        if (!passwordHasher.matches(command.rawPassword(), user.passwordHash())) {
            user.recordFailedLogin();
            userRepository.save(user);
            throw new InvalidCredentialsException();
        }

        if (user.status() != UserStatus.ACTIVE) {
            throw switch (user.status()) {
                case PENDING_VERIFICATION -> new AccountNotVerifiedException();
                case LOCKED -> new AccountLockedException();
                case DISABLED -> new AccountDisabledException();
                case ACTIVE -> throw new IllegalStateException("unreachable");
            };
        }

        user.recordSuccessfulLogin();
        User saved = userRepository.save(user);

        boolean mfaActive = totpCredentialRepository
                .findByUserId(saved.id())
                .map(TotpCredential::isActive)
                .orElse(false);
        if (mfaActive) {
            return new LoginOutcome.MfaChallengeIssued(issueMfaChallenge(saved, tenantId));
        }

        return new LoginOutcome.Authenticated(
                new LoginResult(saved.id().value(), saved.tenantId().value(), saved.email().value()));
    }

    private String issueMfaChallenge(User user, TenantId tenantId) {
        RawVerificationToken rawToken = RawVerificationToken.generate();
        TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
        MfaChallenge challenge = MfaChallenge.issue(user.id(), tenantId, tokenHash, Instant.now(), MFA_CHALLENGE_VALIDITY);
        mfaChallengeRepository.save(challenge);
        return rawToken.value();
    }

    private User findUserOrFail(TenantId tenantId, String rawEmail) {
        try {
            Email email = Email.of(rawEmail);
            return userRepository.findByTenantIdAndEmail(tenantId, email).orElseThrow(InvalidCredentialsException::new);
        } catch (InvalidEmailException ex) {
            // A malformed e-mail can never match a real account - fold it into the exact same
            // generic failure a valid-but-unregistered e-mail produces.
            throw new InvalidCredentialsException();
        }
    }
}
