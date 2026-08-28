package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link ClientSecretHasher} output port with plain SHA-256 - see the port's
 * Javadoc for why a fast, unsalted hash is the right choice here (a client secret, like a
 * verification/reset token, is a high-entropy generated value, not a low-entropy human-chosen
 * one). Mirrors {@link Sha256VerificationTokenHasherAdapter} exactly, plus a constant-time {@link
 * #matches} comparison, since a client secret is checked against one already-known client's
 * stored hash rather than looked up by hash value.
 */
@Component
public class Sha256ClientSecretHasherAdapter implements ClientSecretHasher {

    private static final String ALGORITHM = "SHA-256";

    @Override
    public ClientSecretHash hash(String rawSecret) {
        return ClientSecretHash.of(digest(rawSecret));
    }

    @Override
    public boolean matches(String rawSecret, ClientSecretHash hash) {
        // MessageDigest.isEqual is specified to run in constant time when both arrays are the
        // same length (true here, since both sides are hex digests of the same fixed-size
        // SHA-256 output) - guarding against a timing attack on the comparison itself.
        byte[] candidate = digest(rawSecret).getBytes(StandardCharsets.UTF_8);
        byte[] expected = hash.value().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(candidate, expected);
    }

    private static String digest(String rawSecret) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hashBytes = digest.digest(rawSecret.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available on every conforming JVM (JLS platform
            // requirement), so this can only ever indicate a broken JVM installation.
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
