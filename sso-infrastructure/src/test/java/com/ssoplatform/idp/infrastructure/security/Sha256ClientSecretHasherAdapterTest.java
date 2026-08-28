package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import org.junit.jupiter.api.Test;

class Sha256ClientSecretHasherAdapterTest {

    private final Sha256ClientSecretHasherAdapter hasher = new Sha256ClientSecretHasherAdapter();

    @Test
    void hashProducesA64CharacterHexDigestDifferentFromThePlaintext() {
        String secret = "super-secret-value";

        ClientSecretHash hashed = hasher.hash(secret);

        assertThat(hashed.value()).isNotEqualTo(secret);
        assertThat(hashed.value()).hasSize(64);
        assertThat(hashed.value()).matches("^[0-9a-f]{64}$");
    }

    @Test
    void hashingTheSameSecretTwiceProducesTheSameDigest() {
        String secret = "super-secret-value";

        assertThat(hasher.hash(secret)).isEqualTo(hasher.hash(secret));
    }

    @Test
    void hashingDifferentSecretsProducesDifferentDigests() {
        assertThat(hasher.hash("secret-one")).isNotEqualTo(hasher.hash("secret-two"));
    }

    @Test
    void matchesReturnsTrueForTheCorrectSecret() {
        ClientSecretHash hash = hasher.hash("correct-secret");

        assertThat(hasher.matches("correct-secret", hash)).isTrue();
    }

    @Test
    void matchesReturnsFalseForAnIncorrectSecret() {
        ClientSecretHash hash = hasher.hash("correct-secret");

        assertThat(hasher.matches("wrong-secret", hash)).isFalse();
    }
}
