package com.ssoplatform.idp.domain.mfa;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A candidate 6-digit TOTP code as typed by a user, validated for shape before it is ever compared
 * against a real generated value ({@code TotpCodeVerifier}) - the same "reject malformed input
 * before it reaches a lookup/comparison" style as {@code RawVerificationToken#of}.
 */
public final class TotpCode {

    private static final Pattern VALID_FORMAT = Pattern.compile("^[0-9]{6}$");

    private final String value;

    private TotpCode(String value) {
        this.value = value;
    }

    public static TotpCode of(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            throw new InvalidTotpCodeException("TOTP code must not be blank");
        }
        if (!VALID_FORMAT.matcher(candidate).matches()) {
            throw new InvalidTotpCodeException("TOTP code must be exactly 6 digits");
        }
        return new TotpCode(candidate);
    }

    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TotpCode totpCode)) return false;
        return value.equals(totpCode.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "TotpCode[REDACTED]";
    }
}
