package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RsaJwtSignerAdapterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RsaJwtSignerAdapter signer = new RsaJwtSignerAdapter(objectMapper);

    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    private static Map<String, Object> decodeJsonSegment(ObjectMapper objectMapper, String segment) throws Exception {
        byte[] decoded = Base64.getUrlDecoder().decode(segment);
        return objectMapper.readValue(decoded, Map.class);
    }

    @Test
    void producesAThreePartCompactJws() {
        String jwt = signer.sign(Map.of("sub", "user-1"), keyPair.getPrivate().getEncoded(), "kid-1");

        assertThat(jwt.split("\\.", -1)).hasSize(3);
    }

    @Test
    void headerCarriesRs256TypAndTheGivenKid() throws Exception {
        String jwt = signer.sign(Map.of("sub", "user-1"), keyPair.getPrivate().getEncoded(), "kid-42");

        Map<String, Object> header = decodeJsonSegment(objectMapper, jwt.split("\\.")[0]);

        assertThat(header.get("alg")).isEqualTo("RS256");
        assertThat(header.get("typ")).isEqualTo("JWT");
        assertThat(header.get("kid")).isEqualTo("kid-42");
    }

    @Test
    void payloadRoundTripsEveryClaimExactly() throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "http://acme.localhost:8080");
        claims.put("sub", "11111111-1111-1111-1111-111111111111");
        claims.put("aud", "acme-app");
        claims.put("exp", 1_800_000_000L);
        claims.put("iat", 1_799_999_000L);
        claims.put("nonce", "xyz-nonce");

        String jwt = signer.sign(claims, keyPair.getPrivate().getEncoded(), "kid-1");
        Map<String, Object> payload = decodeJsonSegment(objectMapper, jwt.split("\\.")[1]);

        assertThat(payload.get("iss")).isEqualTo("http://acme.localhost:8080");
        assertThat(payload.get("sub")).isEqualTo("11111111-1111-1111-1111-111111111111");
        assertThat(payload.get("aud")).isEqualTo("acme-app");
        assertThat(payload.get("exp")).isEqualTo(1_800_000_000);
        assertThat(payload.get("iat")).isEqualTo(1_799_999_000);
        assertThat(payload.get("nonce")).isEqualTo("xyz-nonce");
    }

    @Test
    void producesASignatureThatVerifiesAgainstTheMatchingPublicKey() throws Exception {
        String jwt = signer.sign(Map.of("sub", "user-1"), keyPair.getPrivate().getEncoded(), "kid-1");
        String[] parts = jwt.split("\\.");
        String signingInput = parts[0] + "." + parts[1];

        assertThat(verifiesWith(keyPair.getPublic(), signingInput, parts[2])).isTrue();
    }

    @Test
    void producesASignatureThatFailsToVerifyAgainstAnUnrelatedPublicKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PublicKey unrelatedPublicKey = generator.generateKeyPair().getPublic();

        String jwt = signer.sign(Map.of("sub", "user-1"), keyPair.getPrivate().getEncoded(), "kid-1");
        String[] parts = jwt.split("\\.");
        String signingInput = parts[0] + "." + parts[1];

        assertThat(verifiesWith(unrelatedPublicKey, signingInput, parts[2])).isFalse();
    }

    @Test
    void producesASignatureThatFailsToVerifyIfThePayloadIsTampered() throws Exception {
        String jwt = signer.sign(Map.of("sub", "user-1"), keyPair.getPrivate().getEncoded(), "kid-1");
        String[] parts = jwt.split("\\.");
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"sub\":\"someone-else\"}".getBytes(StandardCharsets.UTF_8));
        String tamperedSigningInput = parts[0] + "." + tamperedPayload;

        assertThat(verifiesWith(keyPair.getPublic(), tamperedSigningInput, parts[2])).isFalse();
    }

    private static boolean verifiesWith(PublicKey publicKey, String signingInput, String encodedSignature)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getUrlDecoder().decode(encodedSignature));
    }
}
