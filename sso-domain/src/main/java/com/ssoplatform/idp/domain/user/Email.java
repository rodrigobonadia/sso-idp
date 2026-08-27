package com.ssoplatform.idp.domain.user;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value object representing a validated, normalized e-mail address.
 * Normalization (trim + lowercase) guarantees that "User@Example.com" and
 * "user@example.com" are treated as the same identity when used as a natural key.
 */
public final class Email {

    // Pragmatic RFC 5322-ish validation: good enough to reject obviously malformed input
    // without rejecting valid real-world addresses. Deliverability is verified later
    // via the e-mail verification flow (Phase 2), not by this regex.
    private static final Pattern PATTERN =
            Pattern.compile("^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$");

    private final String value;

    private Email(String value) {
        this.value = value;
    }

    public static Email of(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new InvalidEmailException("Email must not be blank");
        }
        String normalized = rawValue.trim().toLowerCase();
        if (!PATTERN.matcher(normalized).matches()) {
            throw new InvalidEmailException("Email '" + rawValue + "' is not a valid address");
        }
        return new Email(normalized);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Email email)) return false;
        return value.equals(email.value);
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
