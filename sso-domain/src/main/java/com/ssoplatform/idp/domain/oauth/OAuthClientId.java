package com.ssoplatform.idp.domain.oauth;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link OAuthClient} (the internal database identity, not the
 * OAuth-facing {@link ClientId} that appears in requests). */
public final class OAuthClientId {

    private final UUID value;

    private OAuthClientId(UUID value) {
        this.value = value;
    }

    public static OAuthClientId generate() {
        return new OAuthClientId(UUID.randomUUID());
    }

    public static OAuthClientId of(UUID value) {
        Objects.requireNonNull(value, "OAuthClientId value must not be null");
        return new OAuthClientId(value);
    }

    public static OAuthClientId of(String value) {
        Objects.requireNonNull(value, "OAuthClientId value must not be null");
        return new OAuthClientId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OAuthClientId that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
