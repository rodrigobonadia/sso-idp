package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link VerificationTokenHasher} output port with plain SHA-256.
 *
 * <p>Unlike {@link BCryptPasswordHasherAdapter}, this deliberately does not use a slow, salted
 * algorithm: a verification token is a 256-bit value from {@link java.security.SecureRandom}
 * (see {@link RawVerificationToken#generate()}), not a low-entropy user-chosen secret, so it
 * cannot be brute-forced from its hash regardless of hash speed - the property BCrypt's
 * deliberate slowness exists to compensate for.
 */
@Component
public class Sha256VerificationTokenHasherAdapter implements VerificationTokenHasher {

    private static final String ALGORITHM = "SHA-256";

    @Override
    public TokenHash hash(RawVerificationToken rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hashBytes = digest.digest(rawToken.value().getBytes(StandardCharsets.UTF_8));
            return TokenHash.of(HexFormat.of().formatHex(hashBytes));
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available on every conforming JVM (JLS platform
            // requirement), so this can only ever indicate a broken JVM installation.
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
