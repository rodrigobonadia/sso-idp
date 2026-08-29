package com.ssoplatform.idp.infrastructure.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ssoplatform.idp.application.port.out.JwtSigner;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link JwtSigner} output port entirely by hand with {@code java.security} - no
 * JWT library (explicit project decision; {@code jjwt}/Nimbus JOSE+JWT were both considered and
 * rejected, see {@code architecture_decisions.md}) - producing a standard RFC 7515 JWS Compact
 * Serialization string: {@code BASE64URL(header) + "." + BASE64URL(payload) + "." +
 * BASE64URL(signature)}.
 *
 * <p>Always signs with {@code SHA256withRSA} (RS256) - the platform's one and only supported
 * algorithm, matching {@link com.ssoplatform.idp.domain.signingkey.SigningKey#ALGORITHM} - so the
 * header this adapter builds is never configurable, only the {@code kid} varies per call.
 *
 * <p>{@link ObjectMapper} is used purely as a JSON-object-serializer here (turning the header and
 * claims maps into canonical JSON bytes before Base64url-encoding them) - it is already a
 * transitive dependency of every Spring Boot web application via {@code
 * spring-boot-starter-json}, and using it for this is not the same thing as depending on a JWT
 * library: it has no notion of JWTs, claims, or signatures at all, only of JSON.
 */
@Component
public class RsaJwtSignerAdapter implements JwtSigner {

    private static final String JWT_ALG = "RS256";
    private static final String JWT_TYP = "JWT";
    private static final String JAVA_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEY_ALGORITHM = "RSA";

    private final ObjectMapper objectMapper;

    public RsaJwtSignerAdapter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public String sign(Map<String, Object> claims, byte[] privateKeyDer, String keyId) {
        try {
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", JWT_ALG);
            header.put("typ", JWT_TYP);
            header.put("kid", keyId);

            String encodedHeader = base64Url(objectMapper.writeValueAsBytes(header));
            String encodedPayload = base64Url(objectMapper.writeValueAsBytes(claims));
            String signingInput = encodedHeader + "." + encodedPayload;

            PrivateKey privateKey = KeyFactory.getInstance(KEY_ALGORITHM)
                    .generatePrivate(new PKCS8EncodedKeySpec(privateKeyDer));

            Signature signature = Signature.getInstance(JAVA_SIGNATURE_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            String encodedSignature = base64Url(signature.sign());

            return signingInput + "." + encodedSignature;
        } catch (Exception e) {
            // Signing can only fail here because of malformed key material or a broken JVM
            // installation (RSA/SHA-256 are both JLS-guaranteed algorithms) - never because of
            // anything a caller supplied in claims, so this is always a server-side condition.
            throw new IllegalStateException("Failed to sign JWT", e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
