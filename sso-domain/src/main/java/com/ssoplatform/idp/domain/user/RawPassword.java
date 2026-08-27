package com.ssoplatform.idp.domain.user;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value object representing a plaintext password that has passed the platform's
 * strength policy, but has not been hashed yet.
 *
 * <p>This type only ever lives transiently in memory between the moment the user
 * submits a password and the moment {@code PasswordHasher} (an application-layer port,
 * implemented by infrastructure) turns it into a {@link HashedPassword}. It is never
 * persisted and must never appear in logs, which is why {@link #toString()} is redacted.
 */
public final class RawPassword {

    private static final int MIN_LENGTH = 10;
    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("\\d");
    private static final Pattern SPECIAL_CHAR = Pattern.compile("[^A-Za-z0-9]");

    private final String value;

    private RawPassword(String value) {
        this.value = value;
    }

    public static RawPassword of(String candidate) {
        if (candidate == null || candidate.isEmpty()) {
            throw new WeakPasswordException("Password must not be empty");
        }
        if (candidate.length() < MIN_LENGTH) {
            throw new WeakPasswordException("Password must be at least " + MIN_LENGTH + " characters long");
        }
        if (!UPPERCASE.matcher(candidate).find()) {
            throw new WeakPasswordException("Password must contain at least one uppercase letter");
        }
        if (!LOWERCASE.matcher(candidate).find()) {
            throw new WeakPasswordException("Password must contain at least one lowercase letter");
        }
        if (!DIGIT.matcher(candidate).find()) {
            throw new WeakPasswordException("Password must contain at least one digit");
        }
        if (!SPECIAL_CHAR.matcher(candidate).find()) {
            throw new WeakPasswordException("Password must contain at least one special character");
        }
        return new RawPassword(candidate);
    }

    /** Exposed only for the PasswordHasher adapter; never log or persist this value. */
    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RawPassword that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "RawPassword[REDACTED]";
    }
}
