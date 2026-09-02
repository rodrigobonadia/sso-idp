package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RsaJwtVerifierAdapterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RsaJwtSignerAdapter signer = new RsaJwtSignerAdapter(objectMapper);
    private final RsaJwtVerifierAdapter verifier = new RsaJwtVerifierAdapter(objectMapper);

    private KeyPair keyPair;
    private Map<String, byte[]> keysByKeyId;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        keysByKeyId = Map.of("kid-1", keyPair.getPublic().getEncoded());
    }

    private static Map<String, Object> validClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "11111111-1111-1111-1111-111111111111");
        claims.put("iat", Instant.now().getEpochSecond());
        claims.put("exp", Instant.now().plusSeconds(900).getEpochSecond());
        return claims;
    }

    @Test
    void verifiesATokenSignedByTheMatchingPrivateKey() {
        String jwt = signer.sign(validClaims(), keyPair.getPrivate().getEncoded(), "kid-1");

        Optional<Map<String, Object>> result = verifier.verify(jwt, keysByKeyId);

        assertThat(result).isPresent();
        assertThat(result.get().get("sub")).isEqualTo("11111111-1111-1111-1111-111111111111");
    }

    @Test
    void rejectsATokenSignedByAnUnrelatedPrivateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair unrelatedKeyPair = generator.generateKeyPair();
        String jwt = signer.sign(validClaims(), unrelatedKeyPair.getPrivate().getEncoded(), "kid-1");

        assertThat(verifier.verify(jwt, keysByKeyId)).isEmpty();
    }

    @Test
    void rejectsATokenWhoseKidIsNotAmongTheCandidateKeys() {
        String jwt = signer.sign(validClaims(), keyPair.getPrivate().getEncoded(), "kid-unknown");

        assertThat(verifier.verify(jwt, keysByKeyId)).isEmpty();
    }

    @Test
    void rejectsATokenWithATamperedPayload() {
        String jwt = signer.sign(validClaims(), keyPair.getPrivate().getEncoded(), "kid-1");
        String[] parts = jwt.split("\\.");
        String tamperedPayload = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("{\"sub\":\"someone-else\",\"exp\":9999999999}".getBytes(StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + tamperedPayload + "." + parts[2];

        assertThat(verifier.verify(tampered, keysByKeyId)).isEmpty();
    }

    @Test
    void rejectsAnExpiredToken() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "11111111-1111-1111-1111-111111111111");
        claims.put("exp", Instant.now().minusSeconds(60).getEpochSecond());
        String jwt = signer.sign(claims, keyPair.getPrivate().getEncoded(), "kid-1");

        assertThat(verifier.verify(jwt, keysByKeyId)).isEmpty();
    }

    @Test
    void rejectsAMalformedCompactSerialization() {
        assertThat(verifier.verify("not-a-jwt", keysByKeyId)).isEmpty();
        assertThat(verifier.verify("only.two-parts", keysByKeyId)).isEmpty();
        assertThat(verifier.verify(null, keysByKeyId)).isEmpty();
    }

    @Test
    void rejectsATokenWithNoCandidateKeysProvided() {
        String jwt = signer.sign(validClaims(), keyPair.getPrivate().getEncoded(), "kid-1");

        assertThat(verifier.verify(jwt, Map.of())).isEmpty();
    }
}
