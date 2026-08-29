package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.CodeVerifierValidator;
import com.ssoplatform.idp.domain.authorization.CodeChallenge;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link CodeVerifierValidator} output port per RFC 7636 §4.6: a {@code
 * code_verifier} matches a {@link CodeChallenge} when {@code
 * BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))} (unpadded) equals the challenge's stored value -
 * exactly the transform {@code CodeChallenge}'s Javadoc documents as the only one this platform
 * supports.
 *
 * <p>Uses {@link MessageDigest#isEqual(byte[], byte[])} for the final comparison, the same
 * constant-time-for-equal-length-arrays guarantee {@link Sha256ClientSecretHasherAdapter#matches}
 * already relies on, guarding against a timing attack on the comparison itself.
 */
@Component
public class Sha256CodeVerifierValidatorAdapter implements CodeVerifierValidator {

    private static final String ALGORITHM = "SHA-256";

    @Override
    public boolean matches(String codeVerifier, CodeChallenge codeChallenge) {
        if (codeVerifier == null || codeVerifier.isBlank() || codeChallenge == null) {
            return false;
        }
        byte[] candidate = deriveChallenge(codeVerifier).getBytes(StandardCharsets.UTF_8);
        byte[] expected = codeChallenge.value().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(candidate, expected);
    }

    private static String deriveChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to be available on every conforming JVM (JLS platform
            // requirement), so this can only ever indicate a broken JVM installation.
            throw new IllegalStateException(ALGORITHM + " is not available", e);
        }
    }
}
