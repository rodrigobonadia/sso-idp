package com.ssoplatform.idp.domain.oauth;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value object for the OAuth-facing {@code client_id} - the public identifier a client presents
 * in every {@code /authorize} and {@code /token} request. Deliberately distinct from {@link
 * OAuthClientId} (the internal database identity) the same way {@code TenantSlug} is distinct
 * from {@code TenantId}: this value is chosen at provisioning time, appears in URLs/request
 * bodies, and is never treated as a secret - unlike {@link ClientSecretHash}.
 */
public final class ClientId {

    private static final int MAX_LENGTH = 128;
    private static final Pattern PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9_-]{2,127}$");

    private final String value;

    private ClientId(String value) {
        this.value = value;
    }

    public static ClientId of(String rawValue) {
        if (rawValue == null || rawValue.isBlank()) {
            throw new InvalidClientIdException("Client id must not be blank");
        }
        String trimmed = rawValue.trim();
        if (trimmed.length() > MAX_LENGTH) {
            throw new InvalidClientIdException("Client id must not exceed " + MAX_LENGTH + " characters");
        }
        if (!PATTERN.matcher(trimmed).matches()) {
            throw new InvalidClientIdException(
                    "Client id '" + rawValue + "' must be 3-128 characters of letters, digits, '-' or '_', "
                            + "starting with a letter or digit");
        }
        return new ClientId(trimmed);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ClientId that)) return false;
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
