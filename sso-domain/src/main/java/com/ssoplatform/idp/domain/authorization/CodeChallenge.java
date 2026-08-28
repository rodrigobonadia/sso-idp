package com.ssoplatform.idp.domain.authorization;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A PKCE {@code code_challenge} value (RFC 7636), always derived with the {@code S256} transform
 * - this project deliberately does not implement the {@code plain} transform at all (an explicit
 * scope decision: {@code plain} lets the code_verifier travel through the same channel as the
 * challenge in cleartext, which defeats PKCE's entire threat model for the marginal benefit of
 * supporting constrained clients this project does not target - see {@code
 * architecture_decisions.md}). Consequently this type does not carry a "method" field at all: every
 * instance means S256, and {@code code_challenge_method=plain} (or anything other than {@code
 * S256}) is rejected by {@code AuthorizeUseCase} before a {@code CodeChallenge} is ever
 * constructed.
 *
 * <p>Validates the charset RFC 7636 §4.2 specifies for {@code code_challenge} itself: 43-128
 * characters of {@code [A-Za-z0-9-._~]} (unreserved URI characters) - the same shape a base64url,
 * unpadded SHA-256 digest always has (exactly 43 characters), with the wider range left open for
 * future proofing exactly as the RFC allows.
 */
public final class CodeChallenge {

    private static final Pattern VALID_FORMAT = Pattern.compile("^[A-Za-z0-9\\-._~]{43,128}$");

    private final String value;

    private CodeChallenge(String value) {
        this.value = value;
    }

    public static CodeChallenge of(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new InvalidCodeChallengeException("code_challenge must not be blank");
        }
        if (!VALID_FORMAT.matcher(candidate).matches()) {
            throw new InvalidCodeChallengeException("code_challenge has an invalid format");
        }
        return new CodeChallenge(candidate);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CodeChallenge that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
