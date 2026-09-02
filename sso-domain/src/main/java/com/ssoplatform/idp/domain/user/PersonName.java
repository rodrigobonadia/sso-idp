package com.ssoplatform.idp.domain.user;

import java.util.Objects;

/**
 * Value object representing a single component of a person's name (given name or family name).
 *
 * <p>Names are trimmed but otherwise preserved as entered: unlike {@link Email}, case carries
 * meaning for a person's name, so no normalization beyond whitespace trimming is applied.
 */
public final class PersonName {

    // Generous but bounded: prevents obviously-abusive input without rejecting legitimate
    // long names. Chosen to comfortably fit the "given_name"/"family_name" JPA columns.
    private static final int MAX_LENGTH = 100;

    private final String value;

    private PersonName(String value) {
        this.value = value;
    }

    public static PersonName of(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new InvalidPersonNameException("Name must not be blank");
        }
        String trimmed = rawValue.trim();
        if (trimmed.length() > MAX_LENGTH) {
            throw new InvalidPersonNameException("Name must not exceed " + MAX_LENGTH + " characters");
        }
        return new PersonName(trimmed);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PersonName personName)) return false;
        return value.equals(personName.value);
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
