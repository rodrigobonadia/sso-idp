package com.ssoplatform.idp.domain.verification;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A plaintext, single-use verification token: the value actually handed to the user (e.g. as a
 * query parameter in an e-mail link), as opposed to {@link TokenHash}, which is what gets
 * persisted. Never persisted itself and never logged in full - see {@link #toString()} - for the
 * same reason {@code RawPassword} redacts itself in {@code domain.user}.
 */
public final class RawVerificationToken {

    /** 256 bits of entropy: infeasible to guess or brute-force, so no salting is needed when hashing it. */
    private static final int TOKEN_BYTE_LENGTH = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Pattern VALID_FORMAT = Pattern.compile("^[A-Za-z0-9_-]{16,128}$");

    private final String value;

    private RawVerificationToken(String value) {
        this.value = value;
    }

    /** Generates a brand-new, cryptographically random token to hand out (e.g. in a verification link). */
    public static RawVerificationToken generate() {
        byte[] bytes = new byte[TOKEN_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(bytes);
        return new RawVerificationToken(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    /**
     * Wraps a token value received from an external caller (e.g. a {@code ?token=...} query
     * parameter), validating that it at least has the right shape before it's hashed and looked
     * up - malformed input is rejected here rather than surfacing as a confusing "not found" a
     * step later.
     */
    public static RawVerificationToken of(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new InvalidVerificationTokenException("Verification token must not be blank");
        }
        if (!VALID_FORMAT.matcher(candidate).matches()) {
            throw new InvalidVerificationTokenException("Verification token has an invalid format");
        }
        return new RawVerificationToken(candidate);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RawVerificationToken that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "RawVerificationToken[REDACTED]";
    }
}
