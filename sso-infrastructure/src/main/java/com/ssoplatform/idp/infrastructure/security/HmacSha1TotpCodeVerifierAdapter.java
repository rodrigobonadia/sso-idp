package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.TotpCodeVerifier;
import com.ssoplatform.idp.domain.mfa.TotpCode;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link TotpCodeVerifier} output port by hand-rolling RFC 6238 (TOTP) on top of
 * RFC 4226 (HOTP)'s HMAC-based truncation, using only the JDK's own {@code javax.crypto.Mac} -
 * see the port's Javadoc for why no external library is used.
 *
 * <p>Checks the current 30-second time step plus one step on either side ({@link
 * #ALLOWED_STEP_DRIFT}), per RFC 6238 §6's own recommendation, to tolerate ordinary clock drift
 * between the server and the user's device without materially weakening the code's effective
 * validity window (at most ~90 seconds instead of ~30).
 */
@Component
public class HmacSha1TotpCodeVerifierAdapter implements TotpCodeVerifier {

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final int CODE_MODULUS = 1_000_000; // 10^CODE_DIGITS
    private static final long ALLOWED_STEP_DRIFT = 1;

    @Override
    public boolean verify(byte[] rawSecret, TotpCode candidate) {
        long currentStep = (System.currentTimeMillis() / 1000L) / TIME_STEP_SECONDS;
        byte[] candidateBytes = candidate.value().getBytes(StandardCharsets.UTF_8);
        for (long stepOffset = -ALLOWED_STEP_DRIFT; stepOffset <= ALLOWED_STEP_DRIFT; stepOffset++) {
            byte[] expectedBytes = generateCode(rawSecret, currentStep + stepOffset).getBytes(StandardCharsets.UTF_8);
            if (MessageDigest.isEqual(candidateBytes, expectedBytes)) {
                return true;
            }
        }
        return false;
    }

    /** RFC 4226 §5.3's HOTP algorithm: HMAC the 8-byte big-endian time-step counter, then apply
     * "dynamic truncation" to derive a {@link #CODE_DIGITS}-digit decimal code. Package-private
     * (rather than private) specifically so a test can exercise it directly against RFC 6238
     * Appendix B's published test vectors at their fixed historical timestamps - {@link #verify}
     * itself only ever checks against {@code System.currentTimeMillis()}, which a vector-based
     * test cannot control. */
    static String generateCode(byte[] secret, long timeStep) {
        try {
            byte[] counterBytes = ByteBuffer.allocate(8).putLong(timeStep).array();
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret, HMAC_ALGORITHM));
            byte[] hash = mac.doFinal(counterBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int binaryCode = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);
            int truncated = binaryCode % CODE_MODULUS;
            return String.format("%0" + CODE_DIGITS + "d", truncated);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("Failed to compute TOTP code", e);
        }
    }
}
