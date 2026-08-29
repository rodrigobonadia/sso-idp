package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.authorization.CodeChallenge;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class Sha256CodeVerifierValidatorAdapterTest {

    private final Sha256CodeVerifierValidatorAdapter validator = new Sha256CodeVerifierValidatorAdapter();

    private static CodeChallenge challengeFor(String verifier) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.UTF_8));
        return CodeChallenge.of(Base64.getUrlEncoder().withoutPadding().encodeToString(hash));
    }

    @Test
    void matchesTheCorrectVerifierAgainstItsDerivedChallenge() throws Exception {
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        CodeChallenge challenge = challengeFor(verifier);

        assertThat(validator.matches(verifier, challenge)).isTrue();
    }

    @Test
    void rejectsAVerifierThatDoesNotDeriveTheChallenge() throws Exception {
        CodeChallenge challenge = challengeFor("the-real-verifier-value-1234567890");

        assertThat(validator.matches("a-different-verifier-value-0987654321", challenge)).isFalse();
    }

    @Test
    void rejectsANullVerifier() throws Exception {
        CodeChallenge challenge = challengeFor("some-verifier-value-1234567890");

        assertThat(validator.matches(null, challenge)).isFalse();
    }

    @Test
    void rejectsABlankVerifier() throws Exception {
        CodeChallenge challenge = challengeFor("some-verifier-value-1234567890");

        assertThat(validator.matches("   ", challenge)).isFalse();
    }
}
