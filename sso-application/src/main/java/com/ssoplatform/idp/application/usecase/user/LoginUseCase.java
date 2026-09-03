package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.exception.AccountDisabledException;
import com.ssoplatform.idp.application.exception.AccountLockedException;
import com.ssoplatform.idp.application.exception.AccountNotVerifiedException;
import com.ssoplatform.idp.application.exception.InvalidCredentialsException;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.application.port.out.EmailOtpCodeRepository;
import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.MfaChallengeRepository;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.mfa.EmailOtpCode;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.MfaChallenge;
import com.ssoplatform.idp.domain.mfa.MfaMethod;
import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;
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
 * <p>Since Phase 4.2, TWO possible second-factor methods exist - TOTP and e-mail OTP - but a user
 * may have at most one ACTIVE at a time (see {@code EnableEmailOtpUseCase}/{@code
 * EnrollTotpUseCase}), so checking TOTP first and e-mail OTP second is unambiguous: at most one of
 * the two branches below can ever fire. Unlike a TOTP challenge (nothing to do server-side besides
 * issue the bridging token - the user's authenticator app already knows how to produce a code), an
 * e-mail OTP challenge must ALSO generate and send the actual code at this exact moment, since
 * there is no shared secret for the verification step to derive one from later.
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
     * for why this is much shorter than a password-reset token. Also governs the e-mail OTP
     * code's own validity when the active method is {@link MfaMethod#EMAIL_OTP} - see {@code
     * EmailOtpCode}'s Javadoc for why the two are kept equal rather than allowed to drift apart. */
    static final Duration MFA_CHALLENGE_VALIDITY = Duration.ofMinutes(5);

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TotpCredentialRepository totpCredentialRepository;
    private final EmailOtpCredentialRepository emailOtpCredentialRepository;
    private final EmailOtpCodeRepository emailOtpCodeRepository;
    private final EmailOtpCodeHasher emailOtpCodeHasher;
    private final EmailSender emailSender;
    private final MfaChallengeRepository mfaChallengeRepository;
    private final VerificationTokenHasher verificationTokenHasher;

    public LoginUseCase(
            UserRepository userRepository,
            PasswordHasher passwordHasher,
            TotpCredentialRepository totpCredentialRepository,
            EmailOtpCredentialRepository emailOtpCredentialRepository,
            EmailOtpCodeRepository emailOtpCodeRepository,
            EmailOtpCodeHasher emailOtpCodeHasher,
            EmailSender emailSender,
            MfaChallengeRepository mfaChallengeRepository,
            VerificationTokenHasher verificationTokenHasher) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher must not be null");
        this.totpCredentialRepository =
                Objects.requireNonNull(totpCredentialRepository, "totpCredentialRepository must not be null");
        this.emailOtpCredentialRepository =
                Objects.requireNonNull(emailOtpCredentialRepository, "emailOtpCredentialRepository must not be null");
        this.emailOtpCodeRepository =
                Objects.requireNonNull(emailOtpCodeRepository, "emailOtpCodeRepository must not be null");
        this.emailOtpCodeHasher = Objects.requireNonNull(emailOtpCodeHasher, "emailOtpCodeHasher must not be null");
        this.emailSender = Objects.requireNonNull(emailSender, "emailSender must not be null");
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

        boolean totpActive =
                totpCredentialRepository.findByUserId(saved.id()).map(TotpCredential::isActive).orElse(false);
        if (totpActive) {
            String challengeToken = issueMfaChallenge(saved, tenantId, MfaMethod.TOTP);
            return new LoginOutcome.MfaChallengeIssued(challengeToken, MfaMethod.TOTP);
        }

        boolean emailOtpActive = emailOtpCredentialRepository
                .findByUserId(saved.id())
                .map(EmailOtpCredential::isActive)
                .orElse(false);
        if (emailOtpActive) {
            String challengeToken = issueMfaChallenge(saved, tenantId, MfaMethod.EMAIL_OTP);
            return new LoginOutcome.MfaChallengeIssued(challengeToken, MfaMethod.EMAIL_OTP);
        }

        return new LoginOutcome.Authenticated(
                new LoginResult(saved.id().value(), saved.tenantId().value(), saved.email().value()));
    }

    private String issueMfaChallenge(User user, TenantId tenantId, MfaMethod method) {
        RawVerificationToken rawToken = RawVerificationToken.generate();
        TokenHash tokenHash = verificationTokenHasher.hash(rawToken);
        MfaChallenge challenge =
                MfaChallenge.issue(user.id(), tenantId, method, tokenHash, Instant.now(), MFA_CHALLENGE_VALIDITY);
        mfaChallengeRepository.save(challenge);

        if (method == MfaMethod.EMAIL_OTP) {
            sendChallengeCode(user, challenge);
        }
        return rawToken.value();
    }

    /** Generates and e-mails the actual code for an e-mail-OTP challenge - the one thing a TOTP
     * challenge never needs, since the user's authenticator app already has everything it needs
     * to produce a code without this system sending anything. */
    private void sendChallengeCode(User user, MfaChallenge challenge) {
        RawEmailOtpCode rawCode = RawEmailOtpCode.generate();
        EmailOtpCodeHash codeHash = emailOtpCodeHasher.hash(rawCode);
        EmailOtpCode code = EmailOtpCode.issueForChallenge(
                user.id(), challenge.id(), codeHash, Instant.now(), MFA_CHALLENGE_VALIDITY);
        emailOtpCodeRepository.save(code);
        emailSender.sendMfaEmailOtpCode(user.email(), rawCode);
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
