package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link MfaChallenge}. Mirrors {@code SigningKeyId} exactly. */
public final class MfaChallengeId {

    private final UUID value;

    private MfaChallengeId(UUID value) {
        this.value = value;
    }

    public static MfaChallengeId generate() {
        return new MfaChallengeId(UUID.randomUUID());
    }

    public static MfaChallengeId of(UUID value) {
        Objects.requireNonNull(value, "MfaChallengeId value must not be null");
        return new MfaChallengeId(value);
    }

    public static MfaChallengeId of(String value) {
        Objects.requireNonNull(value, "MfaChallengeId value must not be null");
        return new MfaChallengeId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof MfaChallengeId that)) return false;
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
