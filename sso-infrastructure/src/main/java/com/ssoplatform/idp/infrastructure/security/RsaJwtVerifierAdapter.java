package com.ssoplatform.idp.infrastructure.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssoplatform.idp.application.port.out.JwtVerifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link JwtVerifier} output port entirely by hand with {@code java.security} - the
 * mirror image of {@link RsaJwtSignerAdapter}, parsing an RFC 7515 JWS Compact Serialization
 * string back into its header/payload/signature parts and checking it against whichever candidate
 * public key its {@code kid} header claim names.
 *
 * <p>Every failure mode - a malformed compact string, an unsupported {@code alg}, an unrecognized
 * {@code kid}, a signature that does not verify, or an expired token - is collapsed into an empty
 * {@link Optional} return rather than a distinct exception per case; see {@link JwtVerifier}'s
 * Javadoc for why. A handful of these checks (malformed Base64url, unparsable JSON, a missing or
 * non-numeric {@code exp} claim) can also throw a runtime exception from the underlying JDK/Jackson
 * calls - those are caught here too, for the same reason: an attacker-supplied bearer token is
 * exactly the kind of input that must never propagate as a server error.
 */
@Component
public class RsaJwtVerifierAdapter implements JwtVerifier {

    private static final String EXPECTED_ALG = "RS256";
    private static final String JAVA_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEY_ALGORITHM = "RSA";

    private final ObjectMapper objectMapper;

    public RsaJwtVerifierAdapter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Optional<Map<String, Object>> verify(String jwt, Map<String, byte[]> publicKeysByKeyId) {
        try {
            return doVerify(jwt, publicKeysByKeyId);
        } catch (Exception e) {
            // Any parsing/format failure means the presented token is not trustworthy input -
            // never a server-side condition, unlike RsaJwtSignerAdapter#sign's IllegalStateException.
            return Optional.empty();
        }
    }

    private Optional<Map<String, Object>> doVerify(String jwt, Map<String, byte[]> publicKeysByKeyId)
            throws Exception {
        if (jwt == null) {
            return Optional.empty();
        }
        String[] parts = jwt.split("\\.", -1);
        if (parts.length != 3) {
            return Optional.empty();
        }
        String encodedHeader = parts[0];
        String encodedPayload = parts[1];
        String encodedSignature = parts[2];

        Map<String, Object> header = objectMapper.readValue(base64UrlDecode(encodedHeader), Map.class);
        if (!EXPECTED_ALG.equals(header.get("alg"))) {
            return Optional.empty();
        }
        Object kid = header.get("kid");
        if (!(kid instanceof String keyId)) {
            return Optional.empty();
        }
        byte[] publicKeyDer = publicKeysByKeyId.get(keyId);
        if (publicKeyDer == null) {
            return Optional.empty();
        }

        String signingInput = encodedHeader + "." + encodedPayload;
        PublicKey publicKey =
                KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKeyDer));
        Signature signature = Signature.getInstance(JAVA_SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
        if (!signature.verify(base64UrlDecode(encodedSignature))) {
            return Optional.empty();
        }

        Map<String, Object> payload = objectMapper.readValue(base64UrlDecode(encodedPayload), Map.class);
        Object exp = payload.get("exp");
        if (!(exp instanceof Number expNumber)) {
            return Optional.empty();
        }
        if (Instant.now().getEpochSecond() >= expNumber.longValue()) {
            return Optional.empty();
        }

        return Optional.of(payload);
    }

    private static byte[] base64UrlDecode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
