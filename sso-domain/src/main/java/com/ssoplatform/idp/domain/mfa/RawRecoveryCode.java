package com.ssoplatform.idp.domain.mfa;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * A plaintext, single-use MFA recovery ("backup") code: the value shown to the user exactly once
 * at enrollment time, as opposed to the hash actually persisted (see {@link RecoveryCode}). Never
 * persisted itself and never logged in full - see {@link #toString()}.
 *
 * <p>Uses a Crockford-style 32-symbol alphabet (digits and uppercase letters, excluding the
 * visually-ambiguous {@code I}, {@code L}, {@code O}, {@code U}) so a code can be read aloud or
 * typed from a printed sheet without confusion. Ten symbols (5 bits each = 50 bits of entropy),
 * grouped {@code XXXXX-XXXXX} purely for readability - comparable to the entropy budget industry
 * implementations (GitHub, Google) use for the same purpose, which is acceptable specifically
 * because a recovery code is single-use and the account already locks out after repeated failed
 * attempts ({@code User#recordFailedLogin}).
 */
public final class RawRecoveryCode {

    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private static final int SYMBOLS_PER_GROUP = 5;
    private static final int GROUP_COUNT = 2;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String value;

    private RawRecoveryCode(String value) {
        this.value = value;
    }

    /** Generates a brand-new, cryptographically random recovery code to hand out. */
    public static RawRecoveryCode generate() {
        StringBuilder sb = new StringBuilder();
        for (int group = 0; group < GROUP_COUNT; group++) {
            if (group > 0) {
                sb.append('-');
            }
            for (int i = 0; i < SYMBOLS_PER_GROUP; i++) {
                sb.append(ALPHABET.charAt(SECURE_RANDOM.nextInt(ALPHABET.length())));
            }
        }
        return new RawRecoveryCode(sb.toString());
    }

    /** Wraps a code value received from an external caller (e.g. a login-challenge form field),
     * normalizing case/whitespace and validating its shape before it's hashed and looked up. */
    public static RawRecoveryCode of(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new InvalidRecoveryCodeException("Recovery code must not be blank");
        }
        String normalized = candidate.trim().toUpperCase(java.util.Locale.ROOT);
        String[] groups = normalized.split("-");
        if (groups.length != GROUP_COUNT) {
            throw new InvalidRecoveryCodeException("Recovery code has an invalid format");
        }
        for (String group : groups) {
            if (group.length() != SYMBOLS_PER_GROUP) {
                throw new InvalidRecoveryCodeException("Recovery code has an invalid format");
            }
            for (char c : group.toCharArray()) {
                if (ALPHABET.indexOf(c) < 0) {
                    throw new InvalidRecoveryCodeException("Recovery code has an invalid format");
                }
            }
        }
        return new RawRecoveryCode(String.join("-", groups));
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RawRecoveryCode that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "RawRecoveryCode[REDACTED]";
    }
}
