package com.ssoplatform.idp.domain.devicecode;

import java.security.SecureRandom;
import java.util.Objects;

/**
 * The short, human-typeable code a user enters at the verification URI to approve a device (RFC
 * 8628 §3.1's {@code user_code}). Drawn from a restricted 32-character alphabet - the 26 uppercase
 * letters and digits 2-9, excluding {@code 0}/{@code O}, {@code 1}/{@code I}/{@code L} - so a user
 * reading it off a screen (or typing it from memory) never has to disambiguate a letter from a
 * similar-looking digit, mirroring the convention real-world device-flow implementations (e.g.
 * GitHub CLI's {@code gh auth login}) use.
 *
 * <p>Displayed and stored as two groups of 4 separated by a dash (e.g. {@code WDJP-MX9K}) purely
 * for readability; {@link #of(String)} accepts input with or without the dash (or any other
 * non-alphanumeric separator/whitespace a user might add back) and normalizes it before
 * validating.
 */
public final class UserCode {

    private static final String ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    private static final int LENGTH = 8;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String value;

    private UserCode(String value) {
        this.value = value;
    }

    /** Generates a brand-new, cryptographically random user code. */
    public static UserCode generate() {
        StringBuilder sb = new StringBuilder(LENGTH);
        for (int i = 0; i < LENGTH; i++) {
            sb.append(ALPHABET.charAt(SECURE_RANDOM.nextInt(ALPHABET.length())));
        }
        return new UserCode(sb.toString());
    }

    /**
     * Wraps a user code value received from a caller (e.g. the verification page's form field),
     * normalizing it first - stripping any non-alphanumeric characters and uppercasing - before
     * validating that every remaining character belongs to {@link #ALPHABET} and the length is
     * exactly {@value #LENGTH}.
     */
    public static UserCode of(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new InvalidUserCodeException("User code must not be blank");
        }
        String normalized = candidate.replaceAll("[^A-Za-z0-9]", "").toUpperCase();
        if (normalized.length() != LENGTH) {
            throw new InvalidUserCodeException("User code must be exactly " + LENGTH + " characters");
        }
        for (char c : normalized.toCharArray()) {
            if (ALPHABET.indexOf(c) < 0) {
                throw new InvalidUserCodeException("User code contains an invalid character: '" + c + "'");
            }
        }
        return new UserCode(normalized);
    }

    /** The raw 8-character value, with no dash - use {@link #formatted()} for display. */
    public String value() {
        return value;
    }

    /** The value formatted for display/entry: two groups of 4 separated by a dash. */
    public String formatted() {
        return value.substring(0, 4) + "-" + value.substring(4);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserCode that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return formatted();
    }
}
