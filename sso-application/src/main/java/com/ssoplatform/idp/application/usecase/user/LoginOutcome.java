package com.ssoplatform.idp.application.usecase.user;

/**
 * Outcome of {@link LoginUseCase#execute}: either the caller is fully authenticated already
 * ({@link Authenticated}), or the password was correct but a second factor is still required
 * ({@link MfaChallengeIssued}) - in which case no session may be established yet. Modeled as a
 * sealed interface (rather than, say, a nullable field on a single result type) so every caller
 * is forced by the compiler to handle both cases explicitly; see {@code AuthApiController}/{@code
 * LoginPageController} for how the two call sites switch on it.
 */
public sealed interface LoginOutcome {

    /** The caller is fully authenticated - no second factor was required, or none is enrolled. */
    record Authenticated(LoginResult result) implements LoginOutcome {}

    /**
     * The password was correct, but the user has an active TOTP credential - a session must not
     * be established until the second step (a valid code against {@code challengeToken}, via
     * {@code VerifyMfaTotpChallengeUseCase}/{@code VerifyMfaRecoveryCodeChallengeUseCase})
     * succeeds. {@code challengeToken} is the raw, single-use, short-lived value the caller must
     * echo back - only its hash is ever persisted (see {@code MfaChallenge}).
     */
    record MfaChallengeIssued(String challengeToken) implements LoginOutcome {}
}
